// IP段数据
const ipRanges = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
];

// 随机生成一个IP地址，从CIDR段中选择
function generateRandomIP(cidr) {
    const [ip, mask] = cidr.split('/');
    const maskLength = parseInt(mask, 10);
    const ipParts = ip.split('.').map(Number);

    // 将IP转换为32位整数
    const ipInt = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    
    // 计算子网大小
    const subnetSize = Math.pow(2, 32 - maskLength);
    
    // 生成随机偏移量
    const randomOffset = Math.floor(Math.random() * subnetSize);
    
    // 随机生成一个新的IP地址
    const randomIPInt = ipInt + randomOffset;

    // 将生成的32位整数转换回IP地址
    const newIP = [
        (randomIPInt >>> 24) & 255,
        (randomIPInt >>> 16) & 255,
        (randomIPInt >>> 8) & 255,
        randomIPInt & 255
    ].join('.');

    return newIP;
}

// BASE64 编码解码函数
function base64Encode(input) {
    return btoa(input);
}

function base64Decode(input) {
    return atob(input);
}

// 处理节点类型和生成结果
function handleNode() {
    const nodeInput = document.getElementById("nodeInput").value.trim();
    const ipCount = parseInt(document.getElementById("ipCount").value, 10);
    const outputArea = document.getElementById("output");
    const nodeList = nodeInput.split("\n").filter(line => line.trim().length > 0);
    
    let result = "";

    nodeList.forEach(node => {
        // 判断节点类型并处理
        if (node.startsWith("trojan://") || node.startsWith("vless://")) {
            // 对每个节点生成多个随机IP
            for (let i = 0; i < ipCount; i++) {
                // 随机选择一个IP段
                const randomRange = ipRanges[Math.floor(Math.random() * ipRanges.length)];
                const newIP = generateRandomIP(randomRange);
                let newNode = node.replace(/@([^\s:]+):\d+/g, `@${newIP}:443`);
                result += newNode + "\n";
            }
        } else if (node.startsWith("vmess://")) {
            const decodedNode = base64Decode(node.substring(8));
            
            // 替换 vmess 节点中的 "add" 字段，找到 "add": "8cc.free.hr" 类似的部分
            for (let i = 0; i < ipCount; i++) {
                const newIP = generateRandomIP(ipRanges[Math.floor(Math.random() * ipRanges.length)]);
                const updatedNode = decodedNode.replace(/"add":\s*"[^"]+"/g, `"add": "${newIP}"`);
                
                // 重新编码修改后的节点
                const encodedNode = base64Encode(updatedNode);
                result += "vmess://" + encodedNode + "\n";
            }
        }
    });

    outputArea.value = result;
}

// 绑定事件
document.getElementById("generateBtn").addEventListener("click", (e) => {
    e.preventDefault();
    handleNode();
});
