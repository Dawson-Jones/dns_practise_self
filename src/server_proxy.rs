use crate::byte_packet_buffer::{QueryType, DnsPacket, BytePacketBuffer, DnsQuestion, ResultCode};
use std::net::UdpSocket;




fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questioins.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    let _s = socket.send_to(&req_buffer.buf[0..req_buffer.pos], server);

    let mut res_buffer = BytePacketBuffer::new();
    let _r = socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
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

        if let Ok(result) = lookup(&question.name, question.qtype) {
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