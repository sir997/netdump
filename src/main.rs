use anyhow::Result;
use anyhow::{anyhow, Ok};
use bpf::XdpSkelBuilder;
use clap::Parser;
use futures::TryStreamExt;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::time::Duration;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, action=clap::ArgAction::SetTrue)]
    count: bool,
    #[arg(short, long, default_value = "any")]
    iface: String,
    proto: Option<Proto>,
    dir: Option<Dir>,
    tp: Option<TP>,
    value: Option<String>,
}

#[derive(Clone, clap::ValueEnum)]
enum Proto {
    TCP,
    UDP,
    ICMP,
    IP,
    IPV6,
    ARP,
    RARP,
    ETHER,
    WLAN,
}

#[derive(Clone, clap::ValueEnum)]
enum Dir {
    SRC,
    DST,
}

#[derive(Clone, clap::ValueEnum)]
enum TP {
    HOST,
    NET,
    PORT,
    PORTRange,
}

mod bpf;
mod defer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let builder = XdpSkelBuilder::default();
    let skel = builder.open()?;
    let skel = skel.load()?;

    let iface = filter_iface(&cli.iface).await?;
    let fd = skel.progs().xdp_pass().as_fd().as_raw_fd();

    let mut attached: Vec<(u32, String)> = Vec::new();

    let maps = skel.maps();
    let mut builder = RingBufferBuilder::new();
    builder.add(&maps.rb(), handle_event)?;
    let rb = builder.build()?;

    let mode = XDP_FLAGS_DRV_MODE;
    unsafe {
        for (ifindex, ifname) in iface {
            println!(
                "ready to attach: {}, index: {}, fd: {}",
                ifname, ifindex, fd
            );
            let ret = libbpf_sys::bpf_xdp_attach(ifindex as i32, fd, mode, std::ptr::null());
            if ret < 0 {
                release(&attached, fd, mode);
                return Err(anyhow!("iface[{}] attach xdp error, ret: {}", ifname, ret));
            }
            println!("{} has been attached, ret: {}", ifname, ret);

            attached.push((ifindex, ifname));
        }
    }

    ctrlc::set_handler(move || {
        release(&attached, fd, mode);
    })?;

    println!("ready to loop ringbuf");
    while rb.poll(Duration::from_millis(100)).is_ok() {}

    Ok(())
}

fn release(attached: &Vec<(u32, String)>, fd: RawFd, mode: u32) {
    unsafe {
        for (ifindex, ifname) in attached.iter() {
            println!(
                "ready to detach: {}, index: {}, fd: {}",
                ifname, ifindex, fd
            );
            let ret = libbpf_sys::bpf_xdp_detach(*ifindex as i32, mode, std::ptr::null());
            if ret < 0 {
                eprintln!(
                    "iface[{}] detach failed, run `ip link set dev {} xdp off` to manual detach!",
                    ifname, ifname
                );
            } else {
                println!("iface[{}] detach success", ifname);
            }
        }
    }
}

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use libbpf_sys::XDP_FLAGS_DRV_MODE;
use netlink_packet_route::rtnl::link::nlas::Nla;

async fn filter_iface(iface: &str) -> Result<Vec<(u32, String)>> {
    let mut list = Vec::new();

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let mut request = handle.link().get();
    if iface != "" && iface != "any" {
        request = request.match_name(iface.to_string());
    }
    let mut links = request.execute();

    while let Some(link) = links.try_next().await? {
        if !link.nlas.is_empty() {
            if let Nla::IfName(name) = &link.nlas[0] {
                list.push((link.header.index, name.to_owned()));
            } else {
                return Err(anyhow!(
                    "cannot get iface name, index: {}",
                    link.header.index
                ));
            }
        }
    }

    Ok(list)
}

#[repr(C)]
union IpAddr {
    ipv4: u32,
    ipv6: [u32; 4],
}

#[repr(C)]
struct Event {
    eth_proto: u16,
    h_proto: u16,
    length: u32,
    timestamp: u64,
    saddr: IpAddr,
    daddr: IpAddr,
}

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            // 使用IPv4地址的显示格式
            if self.ipv4 != 0 {
                write!(
                    f,
                    "{}.{}.{}.{}",
                    (self.ipv4 >> 24) & 255,
                    (self.ipv4 >> 16) & 255,
                    (self.ipv4 >> 8) & 255,
                    self.ipv4 & 255
                )
            } else {
                // 使用IPv6地址的显示格式
                write!(
                    f,
                    "{:x}:{:x}:{:x}:{:x}",
                    self.ipv6[0], self.ipv6[1], self.ipv6[2], self.ipv6[3],
                )
            }
        }
    }
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() != std::mem::size_of::<Event>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            std::mem::size_of::<Event>()
        );
    }

    let event = unsafe { &*(data.as_ptr() as *const Event) };

    println!("src: {}\tdst: {}\t", event.saddr, event.daddr);

    0
}

#[tokio::test]
async fn filter_iface_test() {
    println!("{:?}", filter_iface("").await);
    println!("{:?}", filter_iface("lo").await);
    println!("{:?}", filter_iface("l").await);
}
