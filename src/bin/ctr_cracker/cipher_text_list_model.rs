use tui::widgets::ListState;

use cryptopals::cyphers::aes::ctr::CTRSampleEncryptions;

use crate::DecryptionProgress;

#[derive(Debug, Clone)]
pub struct CipherTextListModel {
    pub decryption_progress: DecryptionProgress,
    pub state: ListState,
    cursor: usize,
}

impl Default for CipherTextListModel {
    fn default() -> Self {
        let encrypter = CTRSampleEncryptions::new();
        let cipher_texts = encrypter.encrypt_messages();
        let decryption_progress = DecryptionProgress::new(cipher_texts);

        let mut state = ListState::default();
        state.select(Some(0));
        let cursor = 0;

        CipherTextListModel {
            decryption_progress,
            state,
            cursor,
        }
    }
}

impl CipherTextListModel {
    /// Enter a new value for the character at the current cursor position
    ///
    /// Value can be none, in which case the underlying key is set back to zero
    pub fn update_value(&mut self, new_value: Option<u8>) {
        self.decryption_progress.guess_char(
            self.state
                .selected()
                .expect("there is always a selected item"),
            self.h_pos(),
            new_value,
        );

        if new_value.is_some() {
            self.increment_cursor();
        }
    }

    /// Returns the current horizontal position of the cursor
    ///
    /// Note that it is possible for the cursor to be beyond the maximum length
    /// after an index change. In this case this will return the maximum length
    /// and leave the cursor unchanged
    pub fn h_pos(&self) -> usize {
        let maximum_length = self
            .decryption_progress
            .cipher_text_length(self.state.selected().expect("item is always selected"))
            .expect("all cipher texts added to list");
        if self.cursor >= maximum_length {
            maximum_length - 1
        } else {
            self.cursor
        }
    }

    /// Increments the current cursor
    ///
    /// If the cursor is already at the right most position for the currently selected cipher_text
    /// then this method will not increment
    ///
    /// If the cursor is in an illegal position (e.g. beyond the end of the selected text due to an index change)
    /// then this method will shift the cursor to the right-most legal position
    pub fn increment_cursor(&mut self) {
        let maximum_length = self
            .decryption_progress
            .cipher_text_length(self.state.selected().expect("item is always selected"))
            .expect("all cipher texts added to list");
        if self.cursor < maximum_length - 1 {
            self.cursor += 1;
        } else {
            self.cursor = maximum_length - 1;
        }
    }

    /// Decrements the current cursor
    ///
    /// If the cursor is already at the left most position for the currently selected cipher_text (i.e 0)
    /// then this method will not decrement the cursor
    ///
    /// If the cursor is in an illegal position (e.g. beyond the end of the selected text due to an index change)
    /// then this method will shift the cursor to the right-most legal position
    pub fn decrement_cursor(&mut self) {
        let maximum_length = self
            .decryption_progress
            .cipher_text_length(self.state.selected().expect("item is always selected"))
            .expect("all cipher texts added to list");
        if self.cursor >= maximum_length {
            self.cursor = maximum_length - 1;
        } else if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// Increments the current index (vertical selection) - i.e. scrolls up
    ///
    /// If already at maximum index (i.e. top of list) then will wrap and return to bottom of list
    pub fn increment_index(&mut self) {
        if let Some(selected) = self.state.selected() {
            if selected > 0 {
                self.state.select(Some(selected - 1));
            } else {
                self.state
                    .select(Some(self.decryption_progress.cipher_texts.len() - 1));
            }
        }
    }

    /// Increments the current index (vertical selection) - i.e. scrolls down
    ///
    /// If already at maximum index (i.e. bottom of list) then will wrap and return to top of list
    pub fn decrement_index(&mut self) {
        if let Some(selected) = self.state.selected() {
            if selected == self.decryption_progress.cipher_texts.len() - 1 {
                self.state.select(Some(0));
            } else {
                self.state.select(Some(selected + 1));
            }
        }
    }
}
