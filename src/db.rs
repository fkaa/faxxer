use std::{
    borrow::Cow,
    fs::{self, File},
    io::{BufReader, BufWriter},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Database {
    users: Arc<RwLock<UserDatabase>>,
}

impl Database {
    pub fn open(user_path: String) -> Self {
        Database {
            users: Arc::new(RwLock::new(UserDatabase::new(user_path))),
        }
    }

    pub fn get_user(&self, user_id: u64) -> Option<User> {
        let mut inner = self.users.write().unwrap();
        inner.get_user(user_id)
    }

    pub fn get_user_by_code(&self, code: &str) -> Option<User> {
        let mut inner = self.users.write().unwrap();
        inner.get_user_by_code(code)
    }

    pub(crate) fn update_user(&self, user: User) {
        let mut inner = self.users.write().unwrap();
        inner.update_user(user);
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct User {
    pub(crate) user_id: u64,
    pub(crate) username: String,
    pub(crate) prints_left: i32,
    pub(crate) authorize_secret: Option<String>,
}

struct UserDatabase {
    path: String,
}

impl UserDatabase {
    pub fn new(path: String) -> Self {
        if fs::exists(&path).ok() == Some(false) {
            let _ = fs::File::create_new(&path);
        }
        UserDatabase { path }
    }

    pub fn get_user(&self, user_id: u64) -> Option<User> {
        let mut db = self.open_database_read();

        for r in db.records() {
            let Ok(r) = r else {
                return None;
            };
            let user = r.deserialize::<User>(None).unwrap();

            if user.user_id == user_id {
                return Some(user);
            }
        }

        None
    }

    pub fn get_user_by_code(&self, code: &str) -> Option<User> {
        let mut db = self.open_database_read();

        for r in db.records() {
            let Ok(r) = r else {
                return None;
            };
            let user = r.deserialize::<User>(None).unwrap();

            if user.authorize_secret.as_deref() == Some(code) {
                return Some(user);
            }
        }

        None
    }

    pub(crate) fn update_user(&mut self, user: User) {
        let all = self.get_all();
        let all = all.iter().filter(|u| u.user_id != user.user_id);

        {
            let mut db = self.open_temp_database_write();

            db.serialize(&user).unwrap();
            for user in all {
                db.serialize(user).unwrap();
            }
        }

        self.copy_temp_database();
    }

    fn get_all(&self) -> Vec<User> {
        let mut db = self.open_database_read();
        db.records()
            .filter_map(|r| r.ok())
            .filter_map(|r| r.deserialize::<User>(None).ok())
            .collect()
    }
    fn open_database_read(&self) -> csv::Reader<BufReader<File>> {
        let mut rdr =
            csv::ReaderBuilder::new().from_reader(BufReader::new(File::open(&self.path).unwrap()));
        rdr
    }
    fn open_database_write(&mut self) -> csv::Writer<BufWriter<File>> {
        let mut rdr = csv::WriterBuilder::new()
            .from_writer(BufWriter::new(File::create(&self.path).unwrap()));
        rdr
    }
    fn open_temp_database_write(&mut self) -> csv::Writer<BufWriter<File>> {
        let mut rdr = csv::WriterBuilder::new().from_writer(BufWriter::new(
            File::create(&format!("{}.tmp", self.path)).unwrap(),
        ));
        rdr
    }
    fn copy_temp_database(&mut self) {
        fs::rename(&self.path, &format!("{}.bak", self.path)).unwrap();
        fs::rename(&format!("{}.tmp", self.path), &self.path).unwrap();
    }
}
