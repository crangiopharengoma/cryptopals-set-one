use crate::data_access::DecryptionProgress;

mod cipher_text_list_model;
mod data_access;
mod tui_gui;

fn main() {
    tui_gui::run().unwrap();
}
