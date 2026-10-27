//! Cadena inmutable con publicación atómica; HEAD es la única autoridad.
use super::{
    model::{self, Model},
    *,
};
use crate::messages::encode_message;
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const FORMAT: &str = "ardrec-technical-journal-1";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static NEXT: AtomicU64 = AtomicU64::new(0);
type Fault = Box<dyn Fn(&str) -> io::Result<()> + Send>;

/// Almacén Linux local de un único escritor. No interpreta referencias como pruebas físicas.
pub struct TechnicalJournal {
    root: PathBuf,
    _lock: File,
    model: Model,
    sequence: u64,
    tip: String,
    history_bytes: u64,
    poisoned: bool,
    fault: Option<Fault>,
}
fn checked_path(path: &Path) -> Result<()> {
    need(
        path.is_absolute()
            && path
                .components()
                .all(|c| !matches!(c, Component::ParentDir | Component::CurDir)),
        "path_invalid",
    )?;
    for part in path.ancestors() {
        match fs::symlink_metadata(part) {
            Ok(m) => need(!m.file_type().is_symlink(), "symlink_rejected")?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    checked_path(path)?;
    let metadata = fs::symlink_metadata(path)?;
    need(
        metadata.is_file() && metadata.len() <= limit as u64,
        "file_invalid",
    )?;
    let mut raw = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)?;
    need(raw.len() <= limit, "record_too_large")?;
    Ok(raw)
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl TechnicalJournal {
    /// Crear únicamente una carpeta nueva; una creación interrumpida no se presume vacía.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref();
        checked_path(root)?;
        let parent = root.parent().ok_or_else(|| error("path_invalid"))?;
        need(parent.is_dir(), "parent_missing")?;
        fs::DirBuilder::new().mode(0o700).create(root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("LOCK"))?;
        lock.try_lock().map_err(|_| error("lock_unavailable"))?;
        lock.sync_all()?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("records"))?;
        sync_dir(&root.join("records"))?;
        sync_dir(root)?;
        sync_dir(parent)?;
        let mut store = Self {
            root: root.into(),
            _lock: lock,
            model: Model::default(),
            sequence: 0,
            tip: ZERO.into(),
            history_bytes: 0,
            poisoned: false,
            fault: None,
        };
        store.publish_head(0, ZERO)?;
        Ok(store)
    }
    /// Recuperar solo la cadena alcanzable desde HEAD; los huérfanos no se confirman.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref();
        checked_path(root)?;
        let meta = fs::symlink_metadata(root)?;
        need(
            meta.is_dir() && meta.mode() & 0o077 == 0,
            "directory_not_private",
        )?;
        let records = root.join("records");
        checked_path(&records)?;
        need(
            fs::symlink_metadata(&records)?.is_dir(),
            "directory_invalid",
        )?;
        let lock_path = root.join("LOCK");
        read(&lock_path, 0)?;
        need(
            fs::symlink_metadata(&lock_path)?.nlink() == 1,
            "lock_invalid",
        )?;
        let lock = OpenOptions::new().read(true).write(true).open(lock_path)?;
        match lock.try_lock() {
            Ok(()) => (),
            Err(TryLockError::WouldBlock) => return Err(error("lock_busy")),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let raw = read(&root.join("HEAD"), 256)?;
        let value: Value = serde_json::from_slice(&raw).map_err(|_| error("integrity_failure"))?;
        fields(&value, &["format", "sequence", "tip"])?;
        need(
            canonical(&value)? == raw && value["format"] == FORMAT,
            "integrity_failure",
        )?;
        let sequence = value["sequence"]
            .as_u64()
            .ok_or_else(|| error("integrity_failure"))?;
        let tip = text(&value["tip"])?.to_owned();
        need(
            sequence <= MAX_RECORDS && digest_valid(&tip),
            "integrity_failure",
        )?;
        let (mut cursor, mut total) = (tip.clone(), 0_u64);
        let mut chain = Vec::new();
        for expected in (1..=sequence).rev() {
            need(cursor != ZERO && digest_valid(&cursor), "integrity_failure")?;
            let path = records.join(format!("{cursor}.json"));
            let raw = read(&path, MAX_RECORD_BYTES)?;
            total = total
                .checked_add(raw.len() as u64)
                .ok_or_else(|| error("history_limit"))?;
            need(total <= MAX_HISTORY_BYTES, "history_limit")?;
            need(hash(&raw) == cursor, "integrity_failure")?;
            let entry: Value =
                serde_json::from_slice(&raw).map_err(|_| error("integrity_failure"))?;
            fields(
                &entry,
                &["format", "sequence", "previous", "operation", "args"],
            )?;
            need(
                canonical(&entry)? == raw
                    && entry["format"] == FORMAT
                    && entry["sequence"] == expected,
                "integrity_failure",
            )?;
            cursor = text(&entry["previous"])?.to_owned();
            File::open(path)?.sync_all()?;
            chain.push(entry);
        }
        need(cursor == ZERO, "integrity_failure")?;
        let mut model = Model::default();
        for entry in chain.into_iter().rev() {
            need(
                model.apply(text(&entry["operation"])?, &entry["args"])? == Recorded::New,
                "noncanonical_history",
            )?;
        }
        // Confirmar la frontera visible antes de devolver autoridad al consumidor.
        File::open(root.join("HEAD"))?.sync_all()?;
        sync_dir(&records)?;
        sync_dir(root)?;
        Ok(Self {
            root: root.into(),
            _lock: lock,
            model,
            sequence,
            tip,
            history_bytes: total,
            poisoned: false,
            fault: None,
        })
    }
    /// Inyectar fallos controlados en pruebas; no se activa mediante variables del proceso.
    #[doc(hidden)]
    pub fn set_fault_hook(&mut self, hook: impl Fn(&str) -> io::Result<()> + Send + 'static) {
        self.fault = Some(Box::new(hook));
    }
    fn check(&self) -> Result<()> {
        need(!self.poisoned, "recovery_required")
    }
    fn point(&self, name: &str) -> Result<()> {
        if let Some(hook) = &self.fault {
            hook(name)?;
        }
        Ok(())
    }
    fn temp(&self, directory: &Path) -> Result<(PathBuf, File)> {
        for _ in 0..100 {
            let path = directory.join(format!(
                ".tmp-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
        }
        Err(error("temporary_collision"))
    }
    fn write_temp(&self, directory: &Path, raw: &[u8], kind: &str) -> Result<PathBuf> {
        let (path, mut file) = self.temp(directory)?;
        self.point(&format!("{kind}:created"))?;
        let half = raw.len() / 2;
        file.write_all(&raw[..half])?;
        self.point(&format!("{kind}:partial"))?;
        file.write_all(&raw[half..])?;
        self.point(&format!("{kind}:written"))?;
        file.sync_all()?;
        self.point(&format!("{kind}:synced"))?;
        Ok(path)
    }
    fn publish_head(&mut self, sequence: u64, tip: &str) -> Result<()> {
        let raw = canonical(&json!({"format":FORMAT,"sequence":sequence,"tip":tip}))?;
        let temporary = self.write_temp(&self.root, &raw, "head")?;
        self.point("head:before_replace")?;
        fs::rename(temporary, self.root.join("HEAD"))?;
        self.point("head:replaced")?;
        sync_dir(&self.root)?;
        self.point("head:durable")?;
        Ok(())
    }
    fn install(&mut self, raw: &[u8], tip: &str, sequence: u64) -> Result<()> {
        let directory = self.root.join("records");
        let temporary = self.write_temp(&directory, raw, "record")?;
        let target = directory.join(format!("{tip}.json"));
        match fs::hard_link(&temporary, &target) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                need(read(&target, MAX_RECORD_BYTES)? == raw, "integrity_failure")?;
                File::open(&target)?.sync_all()?;
            }
            Err(e) => return Err(e.into()),
        }
        // El contenido se instala sin sobrescribir un registro anterior.
        self.point("record:linked")?;
        fs::remove_file(temporary)?;
        self.point("record:installed")?;
        sync_dir(&directory)?;
        self.point("record:durable")?;
        self.publish_head(sequence, tip)?;
        self.point("commit:acknowledge")?;
        Ok(())
    }
    fn commit(&mut self, op: &str, args: Value) -> Result<Recorded> {
        self.check()?;
        let mut candidate = self.model.clone();
        let recorded = candidate.apply(op, &args)?;
        candidate.audit_temporal()?;
        if recorded == Recorded::Replay {
            return Ok(recorded);
        }
        need(self.sequence < MAX_RECORDS, "history_limit")?;
        let sequence = self.sequence + 1;
        let raw = canonical(
            &json!({"format":FORMAT,"sequence":sequence,"previous":self.tip,"operation":op,"args":args}),
        )?;
        need(
            raw.len() <= MAX_RECORD_BYTES
                && self.history_bytes + raw.len() as u64 <= MAX_HISTORY_BYTES,
            "history_limit",
        )?;
        let tip = hash(&raw);
        if let Err(e) = self.install(&raw, &tip, sequence) {
            self.poisoned = true;
            return Err(e);
        }
        self.model = candidate;
        self.tip = tip;
        self.sequence = sequence;
        self.history_bytes += raw.len() as u64;
        Ok(recorded)
    }
    /// Conservar identidad e intención. Registrar una solicitud no autoriza a ejecutarla.
    pub fn register(&mut self, raw: &[u8]) -> Result<Recorded> {
        let m = model::message(raw)?;
        self.commit("request", json!({"message":m}))
    }
    /// Conservar aceptación, rechazo o resultado completo antes de entregarlo.
    pub fn record_report(&mut self, raw: &[u8]) -> Result<Recorded> {
        let m = model::message(raw)?;
        self.commit("report", json!({"message":m}))
    }
    /// Registrar hechos suministrados por un adaptador confiable, sin fabricar pruebas.
    pub fn observe(&mut self, attempt_id: &str, snapshot: Value) -> Result<Recorded> {
        self.commit(
            "snapshot",
            json!({"attempt_id":attempt_id,"snapshot":snapshot}),
        )
    }
    /// Responder y registrar la pareja consulta/respuesta antes de devolver sus bytes.
    pub fn answer(&mut self, raw: &[u8], response_id: &str, created_at: &str) -> Result<Answer> {
        self.check()?;
        let q = model::message(raw)?;
        need(
            q["message_type"] == "attempt_status_request",
            "query_required",
        )?;
        self.model.audit_temporal()?;
        if let Some(answer) = self.model.replay_query(&q)? {
            return Ok(answer);
        }
        let attempt = self.model.attempt(text(&q["attempt_id"])?)?;
        let response = model::response_for(
            &attempt.request,
            &q,
            &attempt.snapshot,
            response_id,
            &Value::from(created_at),
        );
        let result = if attempt.snapshot["result"]["status"] == "DISPONIBLE" {
            attempt.result.clone()
        } else {
            None
        };
        self.commit(
            "answer",
            json!({"query":q,"response":response,"result":result}),
        )?;
        let (_, answer) = self
            .model
            .answers
            .get(text(&q["message_id"])?)
            .ok_or_else(|| error("query_missing"))?;
        Ok(answer.clone())
    }
    /// Auditar registros recuperados sin reescribirlos ni autorizar ejecuciones.
    pub fn audit_temporal(&self) -> Result<()> {
        self.check()?;
        self.model.audit_temporal()
    }
    /// Copiar el último estado registrado; no afirma que un proceso siga vivo.
    pub fn snapshot(&self, attempt_id: &str) -> Result<Value> {
        self.check()?;
        Ok(self.model.attempt(attempt_id)?.snapshot.clone())
    }
    /// Recuperar el resultado original sin cambiar su identidad ni sus valores exactos.
    pub fn result(&self, attempt_id: &str) -> Result<Option<Vec<u8>>> {
        self.check()?;
        self.model
            .attempt(attempt_id)?
            .result
            .as_ref()
            .map(encode_message)
            .transpose()
            .map_err(Into::into)
    }
    /// Recuperar el primer acuse o rechazo, conservando sus bytes canónicos.
    pub fn first_reply(&self, attempt_id: &str) -> Result<Option<Vec<u8>>> {
        self.check()?;
        self.model
            .attempt(attempt_id)?
            .first_reply
            .as_ref()
            .map(encode_message)
            .transpose()
            .map_err(Into::into)
    }
    /// Número de operaciones publicadas, sin contar temporales ni huérfanos.
    pub fn sequence(&self) -> Result<u64> {
        self.check()?;
        Ok(self.sequence)
    }
}
