use std::{
   env,
   fs,
   path::Path,
};

use age_plugin_fido2_hmac::identity::Identity;

fn main() {
   for path in env::args().skip(1) {
      let path = Path::new(&path);
      let content = fs::read_to_string(path).expect("read file");

      // Extract bech32 line (starts with AGE-PLUGIN-FIDO2-HMAC-)
      let bech32_line = content
         .lines()
         .find(|line| line.starts_with("AGE-PLUGIN-FIDO2-HMAC-"))
         .expect("no AGE-PLUGIN-FIDO2-HMAC- line");

      // Extract created timestamp (legacy lowercase)
      let created = content
         .lines()
         .find_map(|line| line.strip_prefix("# created: "))
         .or_else(|| {
            content
               .lines()
               .find_map(|line| line.strip_prefix("#    Created: "))
         })
         .unwrap_or("unknown");

      // Parse identity to read require_pin and public key
      let id = bech32_line.parse::<Identity>().expect("parse identity");
      let public_key_line = content
         .lines()
         .find(|line| line.contains("public key: age1"))
         .map_or_else(
            || "public key: <unknown>".into(),
            |line| line.trim_start_matches(['#', ' ']).to_owned(),
         );

      // Serial: pull from filename like "name-12345678.pub"
      let stem = path
         .file_stem()
         .and_then(|stem| stem.to_str())
         .unwrap_or("");
      let serial = stem.rsplit_once('-').map_or("", |(_, stem)| stem);

      let pin_policy = if id.require_pin() {
         "required"
      } else {
         "not required"
      };

      let new_content = format!(
         "#     Serial: {serial}\n#    Created: {created}\n# PIN policy: {pin_policy}\n# \
          {public_key_line}\n{bech32_line}\n"
      );
      fs::write(path, new_content).expect("write file");
      println!("updated {}", path.display());
   }
}
