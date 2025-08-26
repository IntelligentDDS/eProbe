/*
 * 读取配置并设置
 */

#include <iostream>
#include <stdlib.h>
#include "../include/yaml-cpp/yaml.h"

// 定义读取config的地址
#define DEFAULT_YAML_PATH "./config/config.yaml"

using namespace std;


struct monitor_addr {
    unsigned int hex_ip;
    std::string name;
    int port;
    std::string hex_ip_right_str;
};

// 记录地址(ip:port)
struct ip_port{
    __u32 ip4;
    __u16 port;
} __attribute__((packed));



// 记录需要监听的IP地址
std::map<std::string, std::string> ip_name_map;                 // pod_ip -> pod_name
std::map<unsigned int, std::string> processid_name_map;                  // process_id -> pod_name 
std::vector<struct monitor_addr> addrs;                         // 记录需要监听的IP地址
std::vector<unsigned int> processids;                                    // 记录需要监听的进程id


// 点分制地址转换为十六进制
int ipToHex(string ip, unsigned int *hex_int){
    // 将点分地址分割
    vector<string> ip_strs;
    int split_loc1 = ip.find(".", 0);               // 第一个.的位置
    int split_loc2 = ip.find(".", split_loc1 + 1 ); // 第二个.的位置
    int split_loc3 = ip.find(".", split_loc2 + 1 ); // 第二个.的位置
    ip_strs.push_back(ip.substr(0, split_loc1));
    ip_strs.push_back(ip.substr(split_loc1 + 1, split_loc2 - 1 - split_loc1));
    ip_strs.push_back(ip.substr(split_loc2 + 1, split_loc3 - 1 - split_loc2));
    ip_strs.push_back(ip.substr(split_loc3 + 1, ip.size() - 1 - split_loc3));

    // 构建十六进制数
    unsigned int temp_hex_int = 0;
    for(int i = 0; i < ip_strs.size(); i ++){
        // 判断地址的有效性
        unsigned int temp_value = std::stoi(ip_strs[i]);
        if( temp_value < 0 || temp_value > 255 ){
            // IP地址输入有问题
            cout << "Error: parsing IP addresses in config.yaml" << endl;
            return -1;
        }
        temp_hex_int = (temp_hex_int << 8) + temp_value;
    }

    *hex_int = temp_hex_int;
    // printf("0x%x\n", temp_hex_int);

    return 0;
}


// 添加需要监听的地址
int addMonitorAddr(YAML::Node monitor_address){
    // 提取IP和名称
    string ip = monitor_address["ip"].as<string>(); 
    string name = monitor_address["name"].as<string>();
    int port = monitor_address["port"].as<int>();

    // 点分制 -> 十六进制 & 十六进制后四位字符
    unsigned int hex_int = 0;
    int ret = ipToHex(ip, &hex_int);
    if(ret != 0){
        // 点分制转十六进制失败
        return ret;
    }

    // 十六进制后四位字符
    char hex_chars[10] = {0};
    sprintf(hex_chars, "%4x", hex_int & 0x0000ffff);
    // cout << hex_chars << endl;
    string hex_right_str = hex_chars;
    cout << hex_right_str << endl;

    // 更新2个map
    ip_name_map[hex_right_str] = name;

    // 更新到vector
    struct monitor_addr temp_addr = {
        .hex_ip = hex_int,
        .name = name,
        .port = port,
        .hex_ip_right_str = hex_right_str,
    };

    addrs.push_back(temp_addr);

    return 0;    
}


// 读取配置文件
int readConfigYaml(std::string config_path){
    // 读取文件
    YAML::Node config = YAML::LoadFile(config_path);

    // 处理监控的服务地址
    YAML::Node monitor_address = config["MonitorAddress"];
    for(int i = 0; i < monitor_address.size(); i ++){
        addMonitorAddr(monitor_address[i]);
    }

    return 0;
}


// 将用户map的数据更新到ebpf map中，通知需要监听的服务地址
int update_target_ip(struct probe_bpf * skel, string ip){
    struct ip_port test_key = {};
    int test_value = 1;
    int map_fd = bpf_map__fd(skel->maps.monitoring_ip_map);

    unsigned int hex_int = 0;
    int ret = ipToHex(ip, &hex_int);
    if(ret != 0){
        // 点分制转十六进制失败
        return ret;
    }
    int update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.monitoring_ip_map), &hex_int, &test_value, BPF_ANY);
    printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);
    
    
    return 0;
}