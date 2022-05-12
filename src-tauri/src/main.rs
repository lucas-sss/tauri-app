#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod skfapi;
mod char_utils;

use crate::skfapi::{SKFApi, DEVINFO};
use crate::char_utils::*;

use libc::{c_uchar, c_uint, strlen};
use libloading::{Library, Symbol};
use std::sync::Mutex;
use std::{hash, str::FromStr};
use tauri::{State, Window};
use std::fmt;


use mac_address;

#[derive(serde::Serialize)]
struct InvokeResponse {
    code: u32,
    message: String,
    data: String,
}

static mut IS_LOGIN: bool = false;

// struct SKFContext<'a> {
//     skf_api: &'a mut SKFApi,
// }
struct AppContext {}

#[tauri::command]
fn login(
    window: Window,
    param: String,
    app_context: State<'_, AppContext>,
) -> Result<InvokeResponse, String> {
    println!("param is: {}", param);
    let mut device_names = String::from("");

    let mut device_num: u32 = 0;
    let mut name_vec: Vec<String> = Vec::new();
    let mut skf_api = SKF_API.lock().unwrap();
    let mut ret = 0;

    ret = skf_api.skf_enum_dev(&mut name_vec, &mut device_num);
    if ret != 0 {
        return Err("枚举设备失败".to_string());
    }
    println!("枚举设备成功");
    println!("device_num: {}", device_num);

    if device_num == 0 {
        return Err("未发现UEKY".to_string());
    } else {
        device_names.push_str(&name_vec.join("||").to_string());
    }
    println!("device names: {}", device_names);
    println!("first device name: {}", name_vec[0]);

    ret = skf_api.skf_connect_dev(&name_vec[0]);
    if ret != 0 {
        println!("连接设备失败, ret: {:x}", ret);
        return Err("连接设备失败".to_string());
    }
    println!("连接设备成功");
    
    let mut dev_info = DEVINFO::new();
    ret = skf_api.skf_get_dev_info(&mut dev_info);
    if ret != 0 {
        println!("获取设备信息失败, ret: {:x}", ret);
        return Err("获取设备信息失败".to_string());
    }
    println!("获取设备信息成功");

    // let label_name = unsafe { String::from_utf8_unchecked(dev_info.label.to_vec()) };
    let label_name = rust_arr_2_c_char(dev_info.label.to_vec());
    println!("设备标签: {}, length: {}", label_name, label_name.len());

    let app_name_str = String::from("flk_identity_app");
    ret = skf_api.skf_open_application(&app_name_str);
    if ret != 0 {
        println!("打开应用失败, ret: {:x}", ret);
        return Err("打开应用失败".to_string());
    }
    println!("打开应用成功");


    let mut retry_count: u32 =0;
    ret = skf_api.skf_verify_pin(&param, &mut retry_count);
    if ret != 0 {
        println!("PIN码验证失败, ret: {:x}, 剩余重试次数: {}", ret, retry_count);
        let s = format!("PIN码验证失败, 剩余重试次数: {}", retry_count);
        return Err(s.to_string());
    }
    println!("PIN码验证成功");

    let con_name_str = String::from("Container");
    ret = skf_api.skf_open_container(&con_name_str);
    if ret != 0 {
        println!("打开容器失败, ret: {:x}", ret);
        return Err("打开容器失败".to_string());
    }
    println!("打开容器成功");


    unsafe {
        IS_LOGIN = true;
    }
    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: String::from(""),
    })
}

#[tauri::command]
fn get_mac(window: Window, skf_context: State<AppContext>) -> Result<InvokeResponse, String> {
    
    let mut mac = String::from("");
    match mac_address::get_mac_address() {
        Ok(Some(ma)) => {
            println!("MAC addr = {}", ma);
            println!("bytes = {:?}", ma.bytes());
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }

    let name = String::from("WLAN");
    match mac_address::mac_address_by_name(&name) {
        Ok(Some(ma)) => {
            println!("MAC addr = {}", ma);
            println!("bytes = {:?}", ma.bytes());
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }


    if mac.len() == 0 {
        return Ok(InvokeResponse {
            code: 1,
            message: String::from("获取mac地址失败"),
            data: String::from(""),
        });
    }

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: mac,
    })
}


#[tauri::command]
fn logout(window: Window, skf_context: State<AppContext>) -> Result<InvokeResponse, String> {
    println!("设备是否已经登录：{}", unsafe { IS_LOGIN });

    let mut ret = 0;
    let mut skf_api = SKF_API.lock().unwrap();

    ret = skf_api.skf_disconnect_dev();
    if ret != 0 {
        println!("设备断开连接失败, ret: {:x}", ret);
        return Err("退出登录失败".to_string());
    }
    println!("设备断开连接成功");

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: String::from(""),
    })
}

//全局静态变量
#[macro_use]
extern crate lazy_static;
lazy_static! {
    static ref SKF_API: Mutex<SKFApi> = Mutex::new(SKFApi::new());
    // static ref SKF_API: SKFApi = {
    //     let mut skfapi = SKFApi::new();
    //     skfapi
    // };
}

fn main() {
    tauri::Builder::default()
        // This is where you pass in your commands
        // .manage(SKFContext { skf_api: &SKF_API })
        .manage(AppContext {})
        .invoke_handler(tauri::generate_handler![login, get_mac, logout])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
