use crate::byte_packet_buffer::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType, ResultCode};
use std::net::{UdpSocket, Ipv4Addr};

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questioins
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    let _s = socket.send_to(&req_buffer.buf[0..req_buffer.pos], server);

    let mut res_buffer = BytePacketBuffer::new();
    let _r = socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    let mut ns ="198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attemptin lookup of {:?} {} with ns {}", qtype, qname, ns);

        let server = (ns, 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // 解析 AUTHORITY SECTION 中的 NS, 并从 ADDITIONAL SECTION 拿到该 NS 的 addr
        if let Some(new_ns)= response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        // 如果没有从 ADDITIONAL SECTION 拿到该 NS 的 addr
        // 重新从 AUTHORITY SECTION 中的 NS 中拿一个
        // 并再一次发起请求, 请求该 NS 的 addr
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        // 如果得到了该 NS 的 addr 继续使用该 addr 进行循环
        let recursize_response = recursive_lookup(&new_ns_name, QueryType::A)?;
        if let Some(new_ns) = recursize_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

pub fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_size, src_addr) = socket.recv_from(&mut req_buffer.buf)?;
    let mut request_packet = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut response_packet = DnsPacket::new();

    response_packet.header.id = request_packet.header.id;
    response_packet.header.recursion_desired = true;
    response_packet.header.recursion_available = true;
    response_packet.header.response = true;

    if let Some(question) = request_packet.questioins.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            response_packet.questioins.push(question);
            response_packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                response_packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                response_packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                response_packet.resources.push(rec);
            }
        } else {
            response_packet.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        response_packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    response_packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src_addr)?;

    Ok(())
}
