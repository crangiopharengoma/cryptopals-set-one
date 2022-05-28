use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{io, thread};

use crossterm::event::{Event as CEvent, KeyCode};
use crossterm::{event, terminal};
use tui::backend::CrosstermBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap};
use tui::Terminal;

use cryptopals::Error;

use crate::cipher_text_list_model::CipherTextListModel;

enum Event<T> {
    Input(T),
    Tick,
}

pub fn run() -> Result<(), Error> {
    terminal::enable_raw_mode().expect("can run in raw mode");

    let (tx, rx) = mpsc::channel();
    let tick_rate = Duration::from_millis(200);
    thread::spawn(move || {
        let mut last_tick = Instant::now();
        loop {
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if event::poll(timeout).expect("poll works") {
                if let CEvent::Key(key) = event::read().expect("can read events") {
                    tx.send(Event::Input(key)).expect("can send events");
                }
            }

            if last_tick.elapsed() >= tick_rate && tx.send(Event::Tick).is_ok() {
                last_tick = Instant::now();
            }
        }
    });

    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    terminal.hide_cursor()?;

    let mut cipher_text_list = CipherTextListModel::default();

    loop {
        terminal.draw(|rect| {
            let size = rect.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(3)
                .constraints([Constraint::Length(3), Constraint::Length(5), Constraint::Min(3)].as_ref())
                .split(size);

            let header = Paragraph::new("Piecemeal Attack on CTR Cipher Text")
                .style(Style::default().fg(Color::White))
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::White))
                        .border_type(BorderType::Rounded),
                );
            rect.render_widget(header, chunks[0]);

            let instructions = Paragraph::new("Attack the poorly encrypted text by guessing characters. Use the arrow keys to scroll about the texts; when you guess one character, the implications for all other texts will be updated. Red highlighted values are non-printable characters; note that this includes carriage return/line feed chars so ended with one or two red asterisks is probably okay. You can overwrite, use backspace or delete to change your entries. ESC will exit this program")
                .style(Style::default().fg(Color::White))
                .alignment(Alignment::Left)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::White))
                        .border_type(BorderType::Rounded),
                )
                .wrap(Wrap { trim: true });
            rect.render_widget(instructions, chunks[1]);


            let list = render_list(cipher_text_list.clone());

            rect.render_stateful_widget(list, chunks[2], &mut cipher_text_list.state);
        })?;

        match rx.recv()? {
            Event::Input(event) => match event.code {
                KeyCode::Char(guess) => cipher_text_list.update_value(Some(guess as u8)),
                KeyCode::Backspace => {
                    cipher_text_list.update_value(None);
                    cipher_text_list.decrement_cursor();
                }
                KeyCode::Delete => cipher_text_list.update_value(None),
                KeyCode::Down => cipher_text_list.decrement_index(),
                KeyCode::Up => cipher_text_list.increment_index(),
                KeyCode::Left => cipher_text_list.decrement_cursor(),
                KeyCode::Right => cipher_text_list.increment_cursor(),
                KeyCode::Esc => {
                    terminal.clear()?;
                    terminal::disable_raw_mode()?;
                    terminal.show_cursor()?;
                    break;
                }
                _ => {}
            },
            Event::Tick => {}
        }
    }

    Ok(())
}

fn render_list(list_model: CipherTextListModel) -> List<'static> {
    let cipher_text_block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::White))
        .title("Cipher Texts")
        .border_type(BorderType::Rounded);

    let items: Vec<_> = list_model
        .decryption_progress
        .progress_text
        .iter()
        .map(|message| {
            ListItem::new::<Spans>(Spans::from(
                message
                    .iter()
                    .enumerate()
                    .map(|(count, decrypted)| {
                        let background_colour = if count == list_model.h_pos() {
                            Color::Yellow
                        } else {
                            Color::Black
                        };

                        match decrypted {
                            Some(byte) => {
                                if byte.likely {
                                    if let Some(outcome) = char::from_u32(byte.outcome as u32) {
                                        Span::styled(
                                            outcome.to_string(),
                                            Style::default().fg(Color::White).bg(background_colour),
                                        )
                                    } else {
                                        Span::styled(
                                            "*".to_string(),
                                            Style::default().fg(Color::White).bg(Color::Red),
                                        )
                                    }
                                } else {
                                    Span::styled(
                                        "*".to_string(),
                                        Style::default().fg(Color::White).bg(Color::Red),
                                    )
                                }
                            }
                            None => Span::styled(
                                "*".to_string(),
                                Style::default().fg(Color::White).bg(background_colour),
                            ),
                        }
                    })
                    .collect::<Vec<Span>>(),
            ))
        })
        .collect();

    let list = List::new(items).block(cipher_text_block).highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::ITALIC),
    );
    list
}
