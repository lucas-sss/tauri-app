#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod char_utils;
mod skfapi;

use crate::char_utils::*;
use crate::skfapi::{SKFApi, DEVINFO, ECCPUBLICKEYBLOB, ECCSIGNATUREBLOB};

use libc::{c_uchar, c_uint, strlen};
use libloading::{Library, Symbol};
use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{hash, str::FromStr};
use tauri::{State, Window};

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
    pin: String,
    app_context: State<'_, AppContext>,
) -> Result<InvokeResponse, String> {
    println!("pin is: {}", pin);
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

    let mut retry_count: u32 = 0;
    ret = skf_api.skf_verify_pin(&pin, &mut retry_count);
    if ret != 0 {
        println!(
            "PIN码验证失败, ret: {:x}, 剩余重试次数: {}",
            ret, retry_count
        );
        let s = format!("PIN码验证失败, 剩余重试次数: {}", retry_count);
        return Err(s.to_string());
    }
    println!("PIN码验证成功");
    let mut user_pin = USER_PIN.lock().unwrap();
    user_pin.clear();
    user_pin.push_str(&pin);

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

    let name = String::from("WLAN");
    match mac_address::mac_address_by_name(&name) {
        Ok(Some(ma)) => {
            println!("WLAN MAC addr: {}", ma);
            // println!("bytes = {:?}", ma.bytes());
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }

    let name1 = String::from("本地连接");
    match mac_address::mac_address_by_name(&name1) {
        Ok(Some(ma)) => {
            println!("本地连接 MAC addr = {}", ma);
            if mac.len() > 0 {
                mac.push_str(",");
            }
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }
    let name2 = String::from("以太网");
    match mac_address::mac_address_by_name(&name1) {
        Ok(Some(ma)) => {
            println!("以太网 MAC addr = {}", ma);
            if mac.len() > 0 {
                mac.push_str(",");
            }
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }

    // match mac_address::get_mac_address() {
    //     Ok(Some(ma)) => {
    //         println!("MAC addr = {}", ma);
    //         println!("bytes = {:?}", ma.bytes());
    //         mac.push_str(&ma.to_string());
    //     }
    //     Ok(None) => println!("No MAC address found."),
    //     Err(e) => println!("{:?}", e),
    // }

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
fn change_pin(
    window: Window,
    newpin: String,
    skf_context: State<AppContext>,
) -> Result<InvokeResponse, String> {
    println!("change_pin -> newpin: {}", newpin);
    let mut ret = 0;

    let mut oldpin = USER_PIN.lock().unwrap();
    let mut skf_api = SKF_API.lock().unwrap();

    let mut retry_count = 6;
    ret = skf_api.skf_change_pin(&oldpin, &newpin, &mut retry_count);
    if ret != 0 {
        println!(
            "更改PIN码失败, ret: {:x}, 剩余重试次数: {}",
            ret, retry_count
        );
        let s = format!("更改PIN码失败, 剩余重试次数: {}", retry_count);
        return Err(s.to_string());
    }

    oldpin.clear();
    oldpin.push_str(&newpin);

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: String::from(""),
    })
}

enum AdminLabel {
    SuperAdmin(u32),
    SystemAdmin(u32),
    SecurityAdmin(u32),
    AuditorAdmin(u32),
}

impl AdminLabel {}

fn convert_ukey_label(label: &str) -> u32 {
    if label == "SuperAdmin" {
        return 1;
    }
    if label == "SystemAdmin" {
        return 2;
    }
    if label == "SecurityAdmin" {
        return 3;
    }
    if label == "AuditorAdmin" {
        return 4;
    }
    return 0;
}

#[tauri::command]
fn generate_auth_data(
    window: Window,
    role: u32,
    pin: String,
    app_context: State<'_, AppContext>,
) -> Result<InvokeResponse, String> {
    println!("generate_auth_data -> role: {}, pin: {}", role, pin);

    let mut ret = 0;
    let data = pin.as_bytes();
    let mut auth_data = String::from("");
    let mut token_y = String::from("");

    if role < 1 || role > 4 {
        return Err("选择角色不存在".to_string());
    }

    let mut skf_api = SKF_API.lock().unwrap();
    // 检测ukey和选择角色是否匹配
    let mut dev_info = DEVINFO::new();
    ret = skf_api.skf_get_dev_info(&mut dev_info);
    if ret != 0 {
        println!("获取设备信息失败, ret: {:x}", ret);
        return Err("获取设备信息失败".to_string());
    }
    let label_name = rust_arr_2_c_char(dev_info.label.to_vec());
    println!("UKEY角色: {}", label_name);
    if role != convert_ukey_label(&label_name) {
        return Err("UKEY与角色不匹配".to_string());
    }

    //生成时间戳
    let mut time_str = String::from("");
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => time_str = n.as_millis().to_string(),
        Err(_) => return Err("获取时间戳失败".to_string()),
    }
    auth_data.push_str(&time_str);
    auth_data.push_str("||");
    token_y.push_str(&time_str);

    //对口令进行hash计算
    let mut cipher_hash = [0u8; 32];
    ret = skf_api.skf_hash(data, data.len() as u32, &mut cipher_hash, false, None);
    if ret != 0 {
        println!("Hash计算失败");
        return Err("口令Hash计算失败".to_string());
    }
    let hex_cipher_hash = hex::encode(&cipher_hash).to_uppercase();
    println!("hex_cipher_hash: {}", hex_cipher_hash);
    auth_data.push_str(&hex_cipher_hash);
    auth_data.push_str("||");
    token_y.push_str(&hex_cipher_hash);

    //生成随机数
    let mut random = [0u8; 16];
    ret = skf_api.skf_gen_random(&mut random, 16);
    if ret != 0 {
        println!("生成随机数失败, ret: {:x}", ret);
        return Err("生成随机数失败".to_string());
    }
    let hex_random = hex::encode(&random).to_uppercase();
    println!("hex_random: {}", hex_random);
    auth_data.push_str(&hex_random);
    auth_data.push_str("||");
    token_y.push_str(&hex_random);
    println!("token_y: {}", token_y);

    //导出签名公钥
    let mut pubkey = ECCPUBLICKEYBLOB::new();
    ret = skf_api.skf_export_public_key(true, &mut pubkey);
    if ret != 0 {
        println!("导出签名公钥失败, ret: {:x}", ret);
        return Err("导出签名公钥失败".to_string());
    }

    let token_y_byte = token_y.as_bytes();
    let mut token_y_hash = [0u8; 32];
    ret = skf_api.skf_hash(
        token_y_byte,
        token_y_byte.len() as u32,
        &mut token_y_hash,
        true,
        Some(pubkey),
    );
    if ret != 0 {
        println!("token哈希计算失败, ret: {:x}", ret);
        return Err("token哈希计算失败".to_string());
    }
    let hex_token_y_hash = hex::encode(&token_y_hash).to_uppercase();
    println!("token_y_hash: {}", hex_token_y_hash);

    let mut signature = ECCSIGNATUREBLOB::new();
    ret = skf_api.skf_sign(&token_y_hash, 32, &mut signature);
    if ret != 0 {
        println!("token签名计算失败, ret: {:x}", ret);
        return Err("token签名计算失败".to_string());
    }
    let sign_str = signature.to_string();
    println!("sign_str: {}", token_y);
    auth_data.push_str(&sign_str);
    auth_data.push_str("||");

    //导出签名证书
    let mut cert = [0u8; 1024];
    let mut cert_len: u32 = 1024;
    ret = skf_api.skf_export_cert(true, &mut cert, &mut cert_len);
    if ret != 0 {
        println!("导出签名证书失败, ret: {:x}", ret);
        return Err("导出签名证书失败".to_string());
    }
    let cert_str = rust_arr_2_c_char(cert.to_vec());
    println!("cert_str: {}", cert_str);
    auth_data.push_str(&cert_str);
    println!("auth data: {}", auth_data);

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: auth_data,
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
    static ref USER_PIN: Mutex<String> = Mutex::new(String::from(""));
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
        .invoke_handler(tauri::generate_handler![
            login,
            generate_auth_data,
            get_mac,
            change_pin,
            logout
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
