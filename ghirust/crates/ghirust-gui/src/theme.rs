//! Centralized semantic palette. No UI code outside this module creates raw
//! colors; everything renders through [`Palette`] tokens so dark/light themes
//! stay consistent and legible.

use eframe::egui::{self, Color32};
use ghirust_core::resources::PressureState;

/// Semantic color tokens. No hardcoded colors anywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub surface: Color32,
    pub surface_alt: Color32,
    pub border: Color32,
    pub text_primary: Color32,
    pub text_secondary: Color32,
    pub text_disabled: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub selection: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub error: Color32,
    pub info: Color32,
    pub link: Color32,
    pub code_bg: Color32,
    pub pressure_normal: Color32,
    pub pressure_warning: Color32,
    pub pressure_high: Color32,
    pub pressure_critical: Color32,
    pub pressure_recovery: Color32,
}

impl Palette {
    pub fn dark() -> Self {
        Self {
            bg: Color32::from_rgb(22, 25, 32),
            panel: Color32::from_rgb(28, 32, 40),
            surface: Color32::from_rgb(34, 40, 52),
            surface_alt: Color32::from_rgb(44, 62, 86),
            border: Color32::from_rgb(78, 96, 122),
            text_primary: Color32::from_rgb(232, 234, 240),
            text_secondary: Color32::from_rgb(168, 176, 188),
            text_disabled: Color32::from_rgb(110, 116, 126),
            accent: Color32::from_rgb(120, 180, 255),
            accent_hover: Color32::from_rgb(150, 200, 255),
            selection: Color32::from_rgb(58, 96, 148),
            success: Color32::from_rgb(120, 220, 140),
            warning: Color32::from_rgb(235, 200, 90),
            error: Color32::from_rgb(235, 110, 110),
            info: Color32::from_rgb(110, 145, 190),
            link: Color32::from_rgb(110, 170, 255),
            code_bg: Color32::from_rgb(18, 21, 27),
            pressure_normal: Color32::from_rgb(120, 220, 140),
            pressure_warning: Color32::from_rgb(235, 200, 90),
            pressure_high: Color32::from_rgb(240, 150, 60),
            pressure_critical: Color32::from_rgb(235, 110, 110),
            pressure_recovery: Color32::from_rgb(110, 170, 255),
        }
    }

    pub fn light() -> Self {
        Self {
            bg: Color32::from_rgb(246, 247, 249),
            panel: Color32::from_rgb(240, 242, 245),
            surface: Color32::from_rgb(255, 255, 255),
            surface_alt: Color32::from_rgb(232, 240, 250),
            border: Color32::from_rgb(200, 205, 214),
            text_primary: Color32::from_rgb(30, 32, 38),
            text_secondary: Color32::from_rgb(80, 86, 96),
            text_disabled: Color32::from_rgb(140, 146, 156),
            accent: Color32::from_rgb(32, 96, 168),
            accent_hover: Color32::from_rgb(50, 120, 200),
            selection: Color32::from_rgb(190, 216, 244),
            success: Color32::from_rgb(30, 140, 60),
            warning: Color32::from_rgb(170, 120, 0),
            error: Color32::from_rgb(190, 40, 40),
            info: Color32::from_rgb(50, 90, 150),
            link: Color32::from_rgb(20, 80, 180),
            code_bg: Color32::from_rgb(250, 250, 252),
            pressure_normal: Color32::from_rgb(30, 140, 60),
            pressure_warning: Color32::from_rgb(170, 120, 0),
            pressure_high: Color32::from_rgb(200, 100, 20),
            pressure_critical: Color32::from_rgb(190, 40, 40),
            pressure_recovery: Color32::from_rgb(20, 80, 180),
        }
    }

    /// Color for a resource pressure state (semantic token).
    pub fn pressure(&self, state: PressureState) -> Color32 {
        match state {
            PressureState::Normal => self.pressure_normal,
            PressureState::Warning => self.pressure_warning,
            PressureState::HighPressure => self.pressure_high,
            PressureState::Critical => self.pressure_critical,
            PressureState::Recovery => self.pressure_recovery,
        }
    }

    /// Apply the palette to an egui context. Theme colors are the only source
    /// of truth; widget visuals are derived from the tokens.
    pub fn apply(&self, context: &egui::Context, dark: bool) {
        let mut visuals = if dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        visuals.override_text_color = Some(self.text_primary);
        visuals.window_fill = self.bg;
        visuals.panel_fill = self.panel;
        visuals.extreme_bg_color = self.bg;
        visuals.faint_bg_color = self.surface;
        visuals.window_stroke = egui::Stroke::new(1.0_f32, self.border);
        visuals.selection.bg_fill = self.selection;
        visuals.selection.stroke = egui::Stroke::new(1.0_f32, self.accent);
        visuals.hyperlink_color = self.link;
        visuals.warn_fg_color = self.warning;
        visuals.error_fg_color = self.error;
        visuals.code_bg_color = self.code_bg;
        context.set_visuals(visuals);

        let mut style = (*context.style()).clone();
        style.visuals = context.style().visuals.clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 4.0);
        context.set_style(style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_and_light_have_distinct_backgrounds_and_readable_text() {
        let dark = Palette::dark();
        let light = Palette::light();
        assert_ne!(dark.bg, light.bg);
        // Text tokens must differ strongly from their backgrounds.
        for (background, text) in [
            (dark.bg, dark.text_primary),
            (dark.bg, dark.text_secondary),
            (light.bg, light.text_primary),
            (light.bg, light.text_secondary),
        ] {
            let luminance = |color: Color32| {
                0.2126 * color.r() as f32 + 0.7152 * color.g() as f32 + 0.0722 * color.b() as f32
            };
            assert!(
                (luminance(text) - luminance(background)).abs() > 40.0,
                "text token has insufficient contrast"
            );
        }
    }

    #[test]
    fn pressure_states_have_semantic_colors() {
        let palette = Palette::dark();
        let states = [
            (PressureState::Normal, palette.pressure_normal),
            (PressureState::Warning, palette.pressure_warning),
            (PressureState::HighPressure, palette.pressure_high),
            (PressureState::Critical, palette.pressure_critical),
            (PressureState::Recovery, palette.pressure_recovery),
        ];
        for (state, expected) in states {
            assert_eq!(palette.pressure(state), expected);
        }
    }
}
