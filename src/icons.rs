//! Program icons for the process column: the icon of an executable as RGBA
//! pixels. Slow enough (file access, GDI) to be called from a background thread.

use crate::util::wide;
use std::ffi::c_void;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS,
    HBITMAP, HDC,
};
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, GetIconInfo, PrivateExtractIconsW, HICON, ICONINFO,
};

/// The size asked for (pixels). Lists draw it at 16-20 points, so this stays
/// sharp on high-DPI screens.
pub const ICON_SIZE: u32 = 32;

/// An RGBA image, straight alpha.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IconImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// The icon of an executable (32x32 or larger), or None.
pub fn extract(exe_path: &str) -> Option<IconImage> {
    let path = exe_path.trim().trim_matches('"');
    if path.is_empty() || !Path::new(path).is_file() {
        return None;
    }
    extract_sized(path).or_else(|| extract_shell(path))
}

/// The first icon of the file itself, at exactly `ICON_SIZE`.
fn extract_sized(path: &str) -> Option<IconImage> {
    let w = wide(path);
    if w.len() > 260 {
        return None;
    }
    let mut name = [0u16; 260];
    name[..w.len()].copy_from_slice(&w);
    let mut icons = [HICON::default(); 1];
    let got = unsafe {
        PrivateExtractIconsW(
            &name,
            0,
            ICON_SIZE as i32,
            ICON_SIZE as i32,
            Some(&mut icons),
            None,
            0,
        )
    };
    if got == 0 || got == u32::MAX || icons[0].is_invalid() {
        return None;
    }
    let img = unsafe { icon_to_rgba(icons[0]) };
    unsafe {
        let _ = DestroyIcon(icons[0]);
    }
    img
}

/// What File Explorer would show for the file (the generic program icon when
/// the file has none of its own).
fn extract_shell(path: &str) -> Option<IconImage> {
    let w = wide(path);
    let mut info = SHFILEINFOW::default();
    let r = unsafe {
        SHGetFileInfoW(
            PCWSTR(w.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(0),
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        )
    };
    if r == 0 || info.hIcon.is_invalid() {
        return None;
    }
    let img = unsafe { icon_to_rgba(info.hIcon) };
    unsafe {
        let _ = DestroyIcon(info.hIcon);
    }
    img
}

unsafe fn bitmap_bits(dc: HDC, bmp: HBITMAP, w: i32, h: i32) -> Option<Vec<u8>> {
    let mut bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h, // top-down
            biPlanes: 1,
            biBitCount: 32,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let lines = GetDIBits(
        dc,
        bmp,
        0,
        h as u32,
        Some(buf.as_mut_ptr() as *mut c_void),
        &mut bi,
        DIB_RGB_COLORS,
    );
    (lines != 0).then_some(buf)
}

/// BGRA pixels from GDI to straight-alpha RGBA. Icons without an alpha
/// channel (all alpha bytes zero) take their transparency from the mask.
pub(crate) fn bgra_to_rgba(px: &mut [u8], mask: Option<&[u8]>) {
    for p in px.as_chunks_mut::<4>().0 {
        p.swap(0, 2);
    }
    if px.as_chunks::<4>().0.iter().all(|p| p[3] == 0) {
        for (i, p) in px.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let transparent = mask
                .and_then(|m| m.get(i * 4))
                .map(|b| *b != 0)
                .unwrap_or(false);
            p[3] = if transparent { 0 } else { 255 };
        }
    }
}

unsafe fn icon_to_rgba(icon: HICON) -> Option<IconImage> {
    let mut info = ICONINFO::default();
    GetIconInfo(icon, &mut info).ok()?;
    let dc = GetDC(HWND::default());
    let mut result = None;
    if !info.hbmColor.is_invalid() {
        // Find the bitmap size by asking for its header.
        let mut probe = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                ..Default::default()
            },
            ..Default::default()
        };
        if GetDIBits(dc, info.hbmColor, 0, 0, None, &mut probe, DIB_RGB_COLORS) != 0 {
            let (w, h) = (probe.bmiHeader.biWidth, probe.bmiHeader.biHeight.abs());
            if w > 0 && h > 0 && w <= 512 && h <= 512 {
                if let Some(mut px) = bitmap_bits(dc, info.hbmColor, w, h) {
                    let mask = if info.hbmMask.is_invalid() {
                        None
                    } else {
                        bitmap_bits(dc, info.hbmMask, w, h)
                    };
                    bgra_to_rgba(&mut px, mask.as_deref());
                    result = Some(IconImage {
                        width: w as u32,
                        height: h as u32,
                        rgba: px,
                    });
                }
            }
        }
    }
    ReleaseDC(HWND::default(), dc);
    if !info.hbmColor.is_invalid() {
        let _ = DeleteObject(info.hbmColor);
    }
    if !info.hbmMask.is_invalid() {
        let _ = DeleteObject(info.hbmMask);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_conversion() {
        // Blue, green, red, alpha -> red, green, blue, alpha.
        let mut px = vec![1, 2, 3, 200, 4, 5, 6, 0];
        bgra_to_rgba(&mut px, None);
        assert_eq!(px, vec![3, 2, 1, 200, 6, 5, 4, 0]);

        // No alpha at all: opaque, except where the mask says transparent.
        let mut old = vec![10, 20, 30, 0, 40, 50, 60, 0];
        let mask = vec![0, 0, 0, 0, 255, 255, 255, 0];
        bgra_to_rgba(&mut old, Some(&mask));
        assert_eq!(old, vec![30, 20, 10, 255, 60, 50, 40, 0]);

        let mut no_mask = vec![10, 20, 30, 0];
        bgra_to_rgba(&mut no_mask, None);
        assert_eq!(no_mask[3], 255);
    }

    #[test]
    fn extracts_a_system_icon() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let img = extract(&format!("{root}\\System32\\notepad.exe"))
            .or_else(|| extract(&format!("{root}\\explorer.exe")));
        let img = img.expect("an icon from a system executable");
        assert!(img.width >= 16 && img.height >= 16);
        assert_eq!(img.rgba.len() as u32, img.width * img.height * 4);
        assert!(
            img.rgba.as_chunks::<4>().0.iter().any(|p| p[3] > 0),
            "icon must not be fully transparent"
        );
        assert!(extract("C:\\missing\\nothing.exe").is_none());
        assert!(extract("").is_none());
    }
}
