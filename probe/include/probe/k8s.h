/*
 * Obtain the IP address of the cni0 interface in a Kubernetes environment.
 */

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define EXEC_RESULT_LEN  500
#define IP_MAX_LEN 20

using namespace std;

// 读取cni0的IP信息，对应于kubelet的发送探针包的IP
string readKubeletProbeIP(){
    FILE *fp = NULL;
	char data[EXEC_RESULT_LEN] = {0};
	char ip_str[IP_MAX_LEN] = {0};
	fp = popen("ip addr | grep cni0", "r"); // 执行指令
	if (fp == NULL)
	{
		printf("popen error!\n");
		return "";
	}
	while (fgets(data, sizeof(data), fp) != NULL)
	{
		printf("%s", data);

		// 获取ip信息
		const char *needle = "inet";
		char *inet_result = strstr(data, needle);
		if (inet_result) {
			char * end_inet_result = strchr(inet_result, '/');
			if (inet_result){
				int ip_len = end_inet_result - inet_result - 5; // 5 为"inet "的长度
				strncpy(ip_str, inet_result + 5, ip_len);
				// printf("ip string: %s\n", ip_str);
			}
			
		}
	}
	pclose(fp);

	return std::string(ip_str);
}