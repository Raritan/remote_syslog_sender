require 'socket'
require 'syslog_protocol'

module RemoteSyslogSender
  class Sender
    # To suppress initialize warning
    class LegacyPacket < SyslogProtocol::Packet
      def initialize(*)
        super
        @time = nil
      end
    end

    class Packet < SyslogProtocol::SyslogRfc5424Packet
      def initialize(*)
        super
        @time = nil
      end
    end

    attr_reader :socket
    attr_accessor :packet

    def initialize(remote_hostname, remote_port, options = {})
      @remote_hostname  = remote_hostname
      @remote_port      = remote_port
      @whinyerrors      = options[:whinyerrors]
      @packet_size      = options[:packet_size] || 1024
      @legacy_format    = !!options[:legacy_format]

      @packet           = @legacy_format ? LegacyPacket.new : Packet.new

      local_hostname    = options[:hostname] || options[:local_hostname] || (Socket.gethostname rescue `hostname`.chomp)
      local_hostname    = 'localhost' if local_hostname.nil? || local_hostname.empty?
      @packet.hostname  = local_hostname

      @packet.facility  = options[:facility] || 'user'
      @packet.severity  = options[:severity] || 'notice'
      @packet.tag       = options[:tag] || options[:program]  || "#{File.basename($0)}[#{$$}]"
      unless @legacy_format
        @packet.appname = options[:appname] || options[:program]  || "#{File.basename($0)}[#{$$}]"
        @packet.procid  = options[:procid] || "-"
        @packet.msgid   = options[:msgid] || "-"
      end

      @socket = nil
    end

    def transmit(message, packet_options = nil)
      message.split(/\r?\n/).each do |line|
        begin
          next if line =~ /^\s*$/
          packet = @packet.dup
          if packet_options
            packet.tag = packet_options[:program] if packet_options[:program]
            packet.hostname = packet_options[:local_hostname] if packet_options[:local_hostname]
            %i(hostname facility severity tag time).each do |key|
              packet.send("#{key}=", packet_options[key]) if packet_options[key]
            end
            unless @legacy_format
              %i(appname procid msgid).each do |key|
                packet.send("#{key}=", packet_options[key]) if packet_options[key]
              end
            end
          end
          packet.content = line
          send_msg(packet.assemble(@packet_size))
        rescue
          if @whinyerrors
            raise
          else
            $stderr.puts "#{self.class} error: #{$!.class}: #{$!}\nOriginal message: #{line}"
          end
        end
      end
    end

    # Make this act a little bit like an `IO` object
    alias_method :write, :transmit

    def close
      @socket.close
    end

    private

    def send_msg(payload)
      raise NotImplementedError, "please override"
    end
  end
end
