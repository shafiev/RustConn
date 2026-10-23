//! Serial protocol options for the connection dialog
//!
//! UI panel for Serial connections with device path, baud rate,
//! data bits, stop bits, parity, and flow control settings.
//! Serial uses an external `picocom` CLI client via VTE terminal.

use adw::prelude::*;
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, DropDown, Entry, StringList};
use libadwaita as adw;
use rustconn_core::{
    SerialBaudRate, SerialDataBits, SerialFlowControl, SerialParity, SerialStopBits,
};

use super::protocol_layout::ProtocolLayoutBuilder;
use super::widgets::EntryRowBuilder;
use crate::i18n::{i18n, i18n_f};

/// Return type for Serial options creation
///
/// Contains:
/// - Container box
/// - Device entry
/// - Baud rate dropdown
/// - Data bits dropdown
/// - Stop bits dropdown
/// - Parity dropdown
/// - Flow control dropdown
/// - Custom args entry
pub type SerialOptionsWidgets = (
    GtkBox,
    Entry,
    DropDown,
    DropDown,
    DropDown,
    DropDown,
    DropDown,
    Entry,
);

/// Creates the Serial options panel using libadwaita components.
///
/// The panel has groups for device settings and line parameters.
#[must_use]
pub fn create_serial_options() -> SerialOptionsWidgets {
    let (container, content) = ProtocolLayoutBuilder::new().build();

    // === Device Group ===
    let device_group = adw::PreferencesGroup::builder()
        .title(i18n("Device"))
        .description(i18n(
            "Serial uses picocom as the terminal client. \
             Ensure your user is in the 'dialout' group for device access.",
        ))
        .build();

    let (device_row, device_entry) = EntryRowBuilder::new(i18n("Device Path"))
        .subtitle(i18n("Path to the serial device"))
        .placeholder("/dev/ttyUSB0")
        .build();
    device_group.add(&device_row);

    // SERIAL-1: Detect available serial devices
    let detect_button = gtk4::Button::builder()
        .label(i18n("Detect Devices"))
        .tooltip_text(i18n("Scan /dev for serial devices, USB adapters first"))
        .valign(gtk4::Align::Center)
        .build();
    let detect_row = adw::ActionRow::builder()
        .title(i18n("Auto-Detect"))
        .subtitle(i18n(
            "Scan for ttyUSB, ttyACM, cu.* (macOS), and ttyS devices",
        ))
        .activatable_widget(&detect_button)
        .build();
    detect_row.add_suffix(&detect_button);
    device_group.add(&detect_row);

    let device_entry_detect = device_entry.clone();
    detect_button.connect_clicked(move |_btn| {
        let names = std::fs::read_dir("/dev")
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let devices = rank_serial_devices(names);
        if let Some(first) = devices.first() {
            device_entry_detect.set_text(first);
            device_entry_detect
                .set_tooltip_text(Some(&i18n_f("Found: {}", &[&devices.join(", ")])));
        } else {
            device_entry_detect.set_tooltip_text(Some(&i18n("No serial devices found")));
        }
    });

    let (custom_args_row, custom_args_entry) = EntryRowBuilder::new(i18n("Custom Arguments"))
        .subtitle(i18n("Additional picocom command-line arguments"))
        .placeholder("--noreset --imap lfcrlf")
        .build();
    device_group.add(&custom_args_row);

    content.append(&device_group);

    // === Line Parameters Group ===
    let line_group = adw::PreferencesGroup::builder()
        .title(i18n("Line Parameters"))
        .description(i18n(
            "Standard serial line configuration (default: 115200 8N1)",
        ))
        .build();

    // Baud rate dropdown
    let baud_model = StringList::new(
        &SerialBaudRate::all()
            .iter()
            .map(|b| b.display_name())
            .collect::<Vec<_>>(),
    );
    let baud_dropdown = DropDown::builder()
        .model(&baud_model)
        .selected(SerialBaudRate::default().index())
        .build();
    let baud_row = adw::ActionRow::builder()
        .title(i18n("Baud Rate"))
        .subtitle(i18n("Communication speed in bits per second"))
        .build();
    baud_row.add_suffix(&baud_dropdown);
    baud_row.set_activatable_widget(Some(&baud_dropdown));
    line_group.add(&baud_row);

    // Data bits dropdown
    let data_bits_model = StringList::new(
        &SerialDataBits::all()
            .iter()
            .map(|d| d.display_name())
            .collect::<Vec<_>>(),
    );
    let data_bits_dropdown = DropDown::builder()
        .model(&data_bits_model)
        .selected(SerialDataBits::default().index())
        .build();
    let data_bits_row = adw::ActionRow::builder()
        .title(i18n("Data Bits"))
        .subtitle(i18n("Number of data bits per character"))
        .build();
    data_bits_row.add_suffix(&data_bits_dropdown);
    data_bits_row.set_activatable_widget(Some(&data_bits_dropdown));
    line_group.add(&data_bits_row);

    // Stop bits dropdown
    let stop_bits_model = StringList::new(
        &SerialStopBits::all()
            .iter()
            .map(|s| s.display_name())
            .collect::<Vec<_>>(),
    );
    let stop_bits_dropdown = DropDown::builder()
        .model(&stop_bits_model)
        .selected(SerialStopBits::default().index())
        .build();
    let stop_bits_row = adw::ActionRow::builder()
        .title(i18n("Stop Bits"))
        .subtitle(i18n("Number of stop bits"))
        .build();
    stop_bits_row.add_suffix(&stop_bits_dropdown);
    stop_bits_row.set_activatable_widget(Some(&stop_bits_dropdown));
    line_group.add(&stop_bits_row);

    // Parity dropdown
    let parity_model = StringList::new(
        &SerialParity::all()
            .iter()
            .map(|p| i18n(p.display_name()))
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let parity_dropdown = DropDown::builder()
        .model(&parity_model)
        .selected(SerialParity::default().index())
        .build();
    let parity_row = adw::ActionRow::builder()
        .title(i18n("Parity"))
        .subtitle(i18n("Error detection scheme"))
        .build();
    parity_row.add_suffix(&parity_dropdown);
    parity_row.set_activatable_widget(Some(&parity_dropdown));
    line_group.add(&parity_row);

    // Flow control dropdown
    let flow_model = StringList::new(
        &SerialFlowControl::all()
            .iter()
            .map(|f| i18n(f.display_name()))
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let flow_dropdown = DropDown::builder()
        .model(&flow_model)
        .selected(SerialFlowControl::default().index())
        .build();
    let flow_row = adw::ActionRow::builder()
        .title(i18n("Flow Control"))
        .subtitle(i18n("Data flow management method"))
        .build();
    flow_row.add_suffix(&flow_dropdown);
    flow_row.set_activatable_widget(Some(&flow_dropdown));
    line_group.add(&flow_row);

    content.append(&line_group);

    (
        container,
        device_entry,
        baud_dropdown,
        data_bits_dropdown,
        stop_bits_dropdown,
        parity_dropdown,
        flow_dropdown,
        custom_args_entry,
    )
}

/// The serial devices among `names` (entries of `/dev`), best candidate first.
///
/// USB adapters before built-in UARTs: a Linux machine typically exposes dozens
/// of `ttyS*` nodes whether or not a port exists, so a plain sort put
/// `/dev/ttyS0` ahead of the `/dev/ttyUSB0` the user just plugged in. Order:
/// `ttyUSB`, `ttyACM`, macOS `cu.usb*`, other `cu.*`, `ttyS`. macOS gets the
/// `cu.*` callout node, not `tty.*`: opening `tty.*` blocks until carrier
/// detect, which a console cable never raises. Within a class, numbered nodes
/// sort by number (`ttyUSB2` before `ttyUSB10`).
fn rank_serial_devices(names: impl IntoIterator<Item = String>) -> Vec<String> {
    const CLASSES: [&str; 5] = ["ttyUSB", "ttyACM", "cu.usb", "cu.", "ttyS"];

    let mut ranked: Vec<(usize, String, u64, String)> = names
        .into_iter()
        .filter_map(|name| {
            let class = CLASSES.iter().position(|prefix| name.starts_with(prefix))?;
            let stem = name.trim_end_matches(|c: char| c.is_ascii_digit());
            let number = name[stem.len()..].parse().unwrap_or(0);
            Some((class, stem.to_string(), number, name))
        })
        .collect();
    ranked.sort();
    ranked
        .into_iter()
        .map(|(_, _, _, name)| format!("/dev/{name}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::rank_serial_devices;

    fn rank(names: &[&str]) -> Vec<String> {
        rank_serial_devices(names.iter().map(|n| (*n).to_string()))
    }

    /// The Linux bug: `ttyS0` sorted ahead of the USB adapter.
    #[test]
    fn a_usb_adapter_beats_the_builtin_uarts() {
        let ranked = rank(&["ttyS0", "ttyS1", "ttyS31", "ttyUSB0", "tty0", "null"]);
        assert_eq!(
            ranked,
            ["/dev/ttyUSB0", "/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS31"]
        );
    }

    #[test]
    fn classes_follow_the_priority_order() {
        let ranked = rank(&[
            "ttyS0",
            "cu.Bluetooth-Incoming-Port",
            "cu.usbserial-1410",
            "ttyACM0",
            "ttyUSB0",
        ]);
        assert_eq!(
            ranked,
            [
                "/dev/ttyUSB0",
                "/dev/ttyACM0",
                "/dev/cu.usbserial-1410",
                "/dev/cu.Bluetooth-Incoming-Port",
                "/dev/ttyS0",
            ]
        );
    }

    /// macOS: the callout `cu.*` node is offered, the dial-in `tty.*` is not.
    #[test]
    fn macos_offers_cu_and_not_tty() {
        let ranked = rank(&["tty.usbserial-1410", "cu.usbserial-1410", "tty.Bluetooth"]);
        assert_eq!(ranked, ["/dev/cu.usbserial-1410"]);
    }

    #[test]
    fn numbered_nodes_sort_by_number() {
        let ranked = rank(&["ttyUSB10", "ttyUSB2", "ttyS10", "ttyS2"]);
        assert_eq!(
            ranked,
            ["/dev/ttyUSB2", "/dev/ttyUSB10", "/dev/ttyS2", "/dev/ttyS10"]
        );
    }

    #[test]
    fn nothing_found_is_empty() {
        assert!(rank(&["null", "tty0", "pts"]).is_empty());
    }
}
