use ctap_fido2::{
   cmd::Authenticator,
   device,
};

fn main() {
   let devs = device::list_devices().expect("list");
   for info in devs {
      let mut auth = match Authenticator::open(&info) {
         Ok(auth) => auth,
         Err(err) => {
            eprintln!("open: {err}");
            continue;
         },
      };
      let i = match auth.info() {
         Ok(i) => i,
         Err(err) => {
            eprintln!("info: {err}");
            continue;
         },
      };
      println!(
         "device: vid={:04x} pid={:04x} product={:?}",
         info.vendor_id, info.product_id, info.product_string
      );
      println!("  versions:   {:?}", i.versions);
      println!("  extensions: {:?}", i.extensions);
      println!("  options:    {:?}", i.options);
   }
}
