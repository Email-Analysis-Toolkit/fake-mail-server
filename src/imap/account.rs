use std::{
    convert::{AsRef, TryFrom},
    path::Path,
};

use imap_codec::types::mailbox::Mailbox;
use rand::Rng;

#[derive(Clone, Debug)]
pub struct Account {
    pub folders: Vec<Folder>,
}

impl Account {
    pub fn from_dir<P: AsRef<Path>>(path: P, folders_p: &[String]) -> std::io::Result<Account> {
        let files = {
            let mut files = Vec::new();

            let directory = std::fs::read_dir(&path)?;

            for entry in directory {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    files.push(entry.path());
                }
            }

            files
        };

        let mut rng = rand::thread_rng();
        let uid: u32 = rng.gen();
        let amt: u32 = files.len() as u32;

        let mut folders = Vec::new();

        for name in folders_p {
            let folder = {
                let mut folder = Folder::new(
                    &[String::from("\\Subscribed")],
                    ".",
                    name,
                    rng.gen::<u32>(),
                    uid + amt + 1,
                );

                if *name == "INBOX" {
                    for (i, path) in files.iter().enumerate() {
                        folder.push_mail(Mail::from_file(path, i as u32 + 1)?);
                    }
                }

                folder
            };

            folders.push(folder);
        }

        Ok(Account { folders })
    }

    pub fn get_folder_by_name(&self, mailbox: &Mailbox) -> Option<Folder> {
        let mailbox = String::try_from(mailbox.clone()).unwrap();

        self.folders
            .iter()
            .find(|folder| folder.name == *mailbox)
            .cloned()
    }
}

#[derive(Clone, Debug)]
pub struct Folder {
    pub flags: Vec<String>,
    pub sep: String,
    pub name: String,
    pub uidvalidity: u32,
    pub mails: Vec<Mail>,
    pub uidnext: u32,
}

impl Folder {
    pub fn new(flags: &[String], sep: &str, name: &str, uidvalidity: u32, uidnext: u32) -> Folder {
        Folder {
            flags: flags.to_owned(),
            sep: sep.to_owned(),
            name: name.to_owned(),
            uidvalidity,
            mails: Vec::new(),
            uidnext,
        }
    }

    pub fn push_mail(&mut self, mail: Mail) {
        self.mails.push(mail);
    }
}

#[derive(Clone, Debug)]
pub struct Mail {
    pub uid: u32,
    pub data: String,
}

impl Mail {
    pub fn from_file<P: AsRef<Path>>(path: P, uid: u32) -> std::io::Result<Mail> {
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("Could not read mail file: \"{:?}\"", path.as_ref()));

        Ok(Mail { uid, data })
    }

    pub fn header(&self) -> String {
        let splits: Vec<_> = self.data.split("\r\n\r\n").collect();
        format!("{}\r\n\r\n", splits[0])
    }

    pub fn body(&self) -> String {
        let splits: Vec<_> = self.data.split("\r\n\r\n").collect();
        format!("{}", splits[1])
    }
}
