using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace ServerMonitor.Controls
{
    class IcmpRequest : BasicRequest
    {
        /// <summary>
        /// 生成一个Icmp请求对象
        /// </summary>
        /// <param name="Domain">请求地址</param>
        public IcmpRequest(IPAddress Domain)
        {
            this.Domain = Domain;
        }

        public override async Task<bool> MakeRequest()
        {
            Color.Clear();
            Time.Clear();
            TTL.Clear();
            Bytes.Clear();
            if (Domain.AddressFamily == AddressFamily.InterNetwork)
            {
                //传入是正确的Ipv4格式
                EndPoint hostEndpoint = (EndPoint)new IPEndPoint(Domain, 1025);
                //循环5次发送icmp包的操作
                for (int i = 0; i < 5; i++)
                {
                    int Datasize = 4;
                    int Packetsize = 8 + Datasize;
                    Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
                    EndPoint clientep = (EndPoint)new IPEndPoint(IPAddress.Parse("127.0.0.1"), 30);
                    IcmpPacket packet = new IcmpPacket(8, 0, 0, 45, 0, Datasize);
                    Byte[] myBuffer = new Byte[Packetsize];
                    int index = packet.CountByte(myBuffer);
                    if (index != Packetsize)
                    {
                        //exception.Text = "报文出现问题";
                        //backData.Add("报文出现问题", "-1");
                        Color.Add("0");
                        return false;
                    }
                    int Cksum_buffer_length = (int)Math.Ceiling(((Double)index) / 2);
                    UInt16[] Cksum_buffer = new UInt16[Cksum_buffer_length];
                    int Icmp_header_buffer_index = 0;
                    for (int j = 0; j < Cksum_buffer_length; j++)
                    {
                        //把两个byte转化为一个uint16
                        Cksum_buffer[j] = BitConverter.ToUInt16(myBuffer, Icmp_header_buffer_index);
                        Icmp_header_buffer_index += 2;
                    }
                    //保存校验和
                    packet.CheckSum = IcmpPacket.SumOfCheck(Cksum_buffer);
                    //将报文转化为数据包
                    Byte[] Senddata = new Byte[Packetsize];
                    index = packet.CountByte(Senddata);
                    //报文出错
                    if (index != Packetsize)
                    {
                        //exception.Text = "报文出错2";
                        //backData.Add("报文出现问题", "0");
                        Color.Add("0");
                        return false;
                    }
                    int Nbytes = 0;
                    //系统计时
                    int starttime = Environment.TickCount;
                    //发送数据包
                    try
                    {
                        try
                        {
                            Nbytes = socket.SendTo(Senddata, Packetsize, SocketFlags.None, hostEndpoint);
                        }
                        catch (Exception SendEx)
                        {
                            //发送异常
                            Color.Add("0");
                            DBHelper.InsertErrorLog(SendEx);
                            Error = SendEx.Message;
                            break;
                        }
                        if (Nbytes == -1)
                        {
                            //exception.Text = "无法传送";
                            //backData.Add("访问被拒绝", "403");
                            Color.Add("0");
                            Error = "Forbidden";
                            return false;
                        }
                        Byte[] Recewivedata = new Byte[256];
                        Nbytes = 0;
                        int Timeout = 0;
                        int timeconsume = 0;
                        while (true)
                        {
                            //socket.Blocking = false;
                            // 这里设置站点超时判断
                            socket.ReceiveTimeout = 1000;
                            try
                            {
                                Nbytes = socket.ReceiveFrom(Recewivedata, 256, SocketFlags.None, ref hostEndpoint);
                            }
                            catch (Exception e)
                            {
                                //服务器连接失败一类的异常  或者超时异常
                                Nbytes = -1;
                                DBHelper.InsertErrorLog(e.InnerException);
                            }
                            if (Nbytes == -1)
                            {
                                //exception.Text = "主机未响应";
                                //backData.Add("主机未响应", "404");
                                Color.Add("0");
                                Error = "Bad Gateway";
                                //return backData;
                                break;
                            }
                            else if (Nbytes > 0)
                            {
                                timeconsume = System.Environment.TickCount - starttime;
                                TimeCost = short.Parse(timeconsume.ToString());
                                //得到与发送间隔时间
                                Time.Add(TimeCost.ToString());
                                TTL.Add(socket.Ttl.ToString());
                                Bytes.Add(Nbytes.ToString());
                                Color.Add("1");
                                break;
                            }
                            Timeout = Environment.TickCount - starttime;
                            if (Timeout > 1000)
                            {
                                Color.Add("-1");
                                break;
                            }
                        }
                        socket.Dispose();
                    }
                    catch (Exception ex)
                    {
                        string s = ex.Message;
                        Color.Add("0");
                        Error = ex.Message;
                        return false;
                    }
                }
                return true;
            }
            else
            {
                Color.Add("0");
                Error = "Unexpected parameters.";
                return false;
            }
        }
        //请求IP
        private IPAddress _domain;
        public IPAddress Domain
        {
            get { return _domain; }
            set { _domain = value; }
        }

        //记录错误信息
        private string _error="";

        public string Error
        {
            get { return _error; }
            set { _error = value; }
        }

        
        //颜色状态
        private List<string> _color = new List<string>();

        public List<string> Color
        {
            get { return _color; }
            set { _color = value;}
        }


        //请求时间
        private List<string> _time = new List<string>();

        public List<string> Time
        {
            get { return _time; }
            set { _time = value; }
        }

        //生存时间
        private List<string> _ttl = new List<string>();

        public List<string> TTL
        {
            get { return _ttl; }
            set { _ttl = value; }
        }


        //数据包
        private List<string> _bytes = new List<string>();

        public List<string> Bytes
        {
            get { return _bytes; }
            set { _bytes = value; }
        }
    }
}
