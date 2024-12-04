require 'socket'
require 'syslog_protocol'
require 'remote_syslog_sender/sender'

module RemoteSyslogSender
  class UdpSender < Sender
    def initialize(remote_hostname, remote_port, options = {})
      super
      type = Socket::AF_INET
      begin
        ip = IPAddr.new(remote_hostname)
        type = Socket::AF_INET6 if ip.ipv6?
      rescue IPAddr::Error
        # ignore
      end
      @socket = UDPSocket.new(type)
    end

    private

    def send_msg(payload)
      @socket.send(payload, 0, @remote_hostname, @remote_port)
    end
  end
end
