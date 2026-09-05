use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceTheme {
    Dark,
    Light,
}

impl InterfaceTheme {
    pub fn background(self) -> tauri::window::Color {
        match self {
            Self::Dark => tauri::window::Color(11, 14, 20, 255),
            Self::Light => tauri::window::Color(244, 247, 251, 255),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_accepts_only_two_fixed_opaque_palettes() {
        for (input, expected) in [("\"dark\"", (11, 14, 20)), ("\"light\"", (244, 247, 251))] {
            let theme: InterfaceTheme = serde_json::from_str(input).unwrap();
            let tauri::window::Color(r, g, b, a) = theme.background();
            assert_eq!((r, g, b), expected);
            assert_eq!(a, 255);
        }
    }

    #[test]
    fn theme_rejects_arbitrary_colors_objects_and_window_targets() {
        for input in [
            "null",
            "0",
            "[]",
            "\"system\"",
            "\"#00000000\"",
            "\"Dark\"",
            "{\"dark\":{\"window\":\"other\"}}",
            "\"dark;cmd.exe\"",
        ] {
            assert!(serde_json::from_str::<InterfaceTheme>(input).is_err());
        }
    }
}
