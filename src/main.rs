mod byte_packet_buffer;

use std::{fs::File, io::{Read, self}, net::UdpSocket};

use byte_packet_buffer::*;


// fn main() -> Result<(), io::Error> {
//     let mut f = File::open("response_packet.txt")?;
//     let mut buffer = BytePacketBuffer::new();

//     f.read(&mut buffer.buf)?;

//     let packet = DnsPacket::from_buffer(&mut buffer).unwrap();
//     println!("{:#?}", packet.header);

//     for q in packet.questioins {
//         println!("{:#?}", q);
//     }

//     for rec in packet.answers {
//         println!("{:#?}", rec)
//     }
    
//     for rec in packet.authorities {
//         println!("{:#?}", rec)
//     }

//     for rec in packet.resources {
//         println!("{:#?}", rec)
//     }

//     Ok(())
// }


// fn main() -> Result<(), io::Error> {
//     let mut f = File::open("query_packet.txt")?;
//     let mut q_buffer = BytePacketBuffer::new();
//     let size = f.read(&mut q_buffer.buf)?;
//     println!("{:02x?}", &q_buffer.buf[0..size]);


//     let d = DnsPacket::from_buffer(&mut q_buffer).unwrap();
//     println!("{:#?}", d);

//     let srv = ("8.8.8.8", 53);
//     let cli = UdpSocket::bind(("0.0.0.0", 43210))?;

//     let _size = cli.send_to(&q_buffer.buf[0..size], srv)?;

//     let mut r_buffer = BytePacketBuffer::new();

//     let _r = cli.recv_from(&mut r_buffer.buf)?;
//     println!("{:02x?}", r_buffer.buf);

//     let res_packet = DnsPacket::from_buffer(&mut r_buffer).unwrap();
//     println!("{:#?}", res_packet);

//     for q in res_packet.questioins {
//         println!("{:#?}", q);
//     }

//     for rec in res_packet.answers {
//         println!("{:#?}", rec);
//     }
//     for rec in res_packet.authorities {
//         println!("{:#?}", rec);
//     }
//     for rec in res_packet.resources {
//         println!("{:#?}", rec);
//     }

//     Ok(())
// }

fn main() -> Result<(), io::Error> {
    let qname = "google.com";
    let qtype = QueryType::A;

    let server = ("8.8.8.8", 53);

    let cli = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 12745;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.header.authed_data = true;
    packet.questioins.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    println!("{:#?}", packet);
    println!("{:02x?}", req_buffer.buf);

    let _s = cli.send_to(&req_buffer.buf[0..req_buffer.pos], server);

    let mut res_buffer = BytePacketBuffer::new();
    let _r = cli.recv_from(&mut res_buffer.buf)?;
    println!("{:02x?}", res_buffer.buf);

    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();
    println!("{:#?}", res_packet);

    for q in res_packet.questioins {
        println!("{:#?}", q);
    }

    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}

// nc -u -l 1053 > query_packet.txt
// nc -u 8.8.8.8 53 < query_packet.txt > response_packet.txt


