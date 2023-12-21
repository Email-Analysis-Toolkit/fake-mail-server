#![allow(dead_code)]
extern crate zmq;

pub fn get_part(uid: u32, part_str: &str) -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("get_part {} {}", uid, part_str)
        .as_str()
        .as_bytes()
        .to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn get_part_headers(uid: u32, part_str: &str) -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("get_part_headers {} {}", uid, part_str)
        .as_str()
        .as_bytes()
        .to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn get_bodystructure(uid: u32) -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("bodystructure {}", uid)
        .as_str()
        .as_bytes()
        .to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn get_headers(uid: u32) -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("headers {}", uid).as_str().as_bytes().to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn get_body(uid: u32) -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("body {}", uid).as_str().as_bytes().to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn get_size(uid: u32) -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("size {}", uid).as_str().as_bytes().to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn idle() -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("idle").as_str().as_bytes().to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}

pub fn search() -> String {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REQ).unwrap();
    socket.connect("ipc:///tmp/oracle.ipc").unwrap();
    let data = format!("search").as_str().as_bytes().to_owned();
    socket.send(data, 0).unwrap();
    socket.recv_msg(0).unwrap().as_str().unwrap().to_string()
}
