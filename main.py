from flask import Flask, render_template, request
from scapy.all import *

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("input.html")


@app.route("/topk", methods=['post'])
def topk():
    k1 = int(request.form.get("frequency"))
    k2 = int(request.form.get("packet"))
    # k1=70
    # k2=70
    #抓包
    # dpkt = sniff(count=100000)  # 这里是针对单网卡的机子，多网卡的可以在参数中指定网卡
    # wrpcap("demo.pcap", dpkt)

    #分析
    dpkt = rdpcap("C:\\Users\\ZHENG LINYING\\Desktop\\demo.pcap")#读包
    vp = [0]
    vf = [0]
    cnt2 = 0
    cnt3 = 0
    dic1 = {}
    dic2 = {}
    cnt4 = 0
    length2 = 0
    for cnt in range(len(dpkt)):
        cnt4 += 1
        # 如过不是IP协议 就跳过 2048 代表IP协议
        if dpkt[cnt][Ether].type != 2048:
            continue

        # 如果不是TCP和UDP 就跳过
        if dpkt[cnt][IP].proto != 6 and dpkt[cnt][IP].proto != 17:
            continue

        # 获得协议类型proto  6是TCP 17是UDP
        if dpkt[cnt][IP].proto == 6:
            proto = "TCP"
        if dpkt[cnt][IP].proto == 17:
            proto = "UDP"

        # 获得IP地址
        ip_src = dpkt[cnt][IP].src
        ip_dst = dpkt[cnt][IP].dst

        # 获得端口
        sport = dpkt[cnt][proto].sport
        dport = dpkt[cnt][proto].dport

        #五元组
        tup = (ip_src, sport, ip_dst, dport, proto)

        # 获得这个包的长度
        length = len(dpkt[cnt])

        #建立dict
        counts = dic1.get(tup, 0)
        dic1[tup] = counts + length
        dic2[tup] = counts + 1



        #作图数据
        cnt2 += 1
        length2 += length
        if cnt4 % 1000 != 0:
            vp[cnt3] = length2
            vf[cnt3] = cnt2
        else:
            cnt3 += 1
            vp.append(length2)
            vf.append(cnt2)


    return render_template("topk.html", K1 = k1, K2 = k2, p = vp, f = vf,  pa = dic1, fre = dic2 )




if __name__ == '__main__':
    app.run("",5000,debug=True)




