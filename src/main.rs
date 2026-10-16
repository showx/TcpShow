mod app;
mod ca;
mod guide;
mod lan;
mod proxy;
mod store;
mod sysproxy;

use std::sync::Arc;

fn main() -> eframe::Result<()> {
    ca::install_crypto();
    let icon = load_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 780.0])
            .with_min_inner_size([960.0, 600.0])
            .with_title("TcpShow")
            .with_icon(Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(
        "TcpShow",
        options,
        Box::new(|cc| Ok(Box::new(app::TcpShowApp::new(cc)))),
    )
}

fn load_icon() -> egui::IconData {
    let img = image::load_from_memory(include_bytes!("../Icon.png"))
        .expect("Icon.png")
        .into_rgba8();
    let (width, height) = img.dimensions();
    egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    }
}
