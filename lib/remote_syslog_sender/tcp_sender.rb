require 'socket'
require 'timeout'
require 'syslog_protocol'
require 'remote_syslog_sender/sender'

module RemoteSyslogSender
  class TcpSender < Sender
    class NonBlockingTimeout < StandardError; end

    def initialize(remote_hostname, remote_port, options = {})
      super
      @tls             = options[:tls]
      @retry_limit     = options[:retry_limit] || 3
      @retry_interval  = options[:retry_interval] || 0.5
      @remote_hostname = remote_hostname
      @remote_port     = remote_port
      @ssl_method      = options[:ssl_method] || :TLSv1_2
      @ssl_min_version = options[:ssl_min_version]
      @ssl_max_version = options[:ssl_max_version]
      @ca_file         = options[:ca_file]
      @verify_mode     = options[:verify_mode]
      @client_cert     = options[:client_cert]
      @client_cert_key = options[:client_cert_key]
      @client_cert_key_pass = options[:client_cert_key_pass]
      @timeout         = options[:timeout] || 600
      @timeout_exception   = !!options[:timeout_exception]
      @exponential_backoff = !!options[:exponential_backoff]
      @tcp_user_timeout = options[:tcp_user_timeout]

      @mutex = Mutex.new
      @tcp_socket = nil

      if [:SOL_SOCKET, :SO_KEEPALIVE, :IPPROTO_TCP, :TCP_KEEPIDLE].all? {|c| Socket.const_defined? c}
        @keep_alive      = options[:keep_alive]
      end
      if Socket.const_defined?(:TCP_KEEPIDLE)
        @keep_alive_idle = options[:keep_alive_idle]
      end
      if Socket.const_defined?(:TCP_KEEPCNT)
        @keep_alive_cnt  = options[:keep_alive_cnt]
      end
      if Socket.const_defined?(:TCP_KEEPINTVL)
        @keep_alive_intvl = options[:keep_alive_intvl]
      end
      connect
    end

    def close
      @socket.close if @socket
      @tcp_socket.close if @tcp_socket
    end

    private

    def connect
      connect_retry_count = 1
      connect_retry_limit = @retry_limit
      connect_retry_interval = @retry_interval
      @mutex.synchronize do
        begin
          close

          if @timeout && @timeout >= 0
            Timeout.timeout(@timeout) do
              @tcp_socket = TCPSocket.new(@remote_hostname, @remote_port)
            end
          else
            @tcp_socket = TCPSocket.new(@remote_hostname, @remote_port)
          end

          @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_USER_TIMEOUT, @tcp_user_timeout) if @tcp_user_timeout

          if @keep_alive
            @tcp_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
            @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPIDLE, @keep_alive_idle) if @keep_alive_idle
            @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPCNT, @keep_alive_cnt) if @keep_alive_cnt
            @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPINTVL, @keep_alive_intvl) if @keep_alive_intvl
          end
          if @tls
            require 'openssl'

            min_max_available = true
            tls_versions_map = {}
            begin
              tls_versions_map = {
                TLSv1: OpenSSL::SSL::TLS1_VERSION,
                TLSv1_1: OpenSSL::SSL::TLS1_1_VERSION,
                TLSv1_2: OpenSSL::SSL::TLS1_2_VERSION
              }
              tls_versions_map[:TLSv1_3] = OpenSSL::SSL::TLS1_3_VERSION if defined?(OpenSSL::SSL::TLS1_3_VERSION)
            rescue NameError
              # ruby 2.4 doesn't have OpenSSL::SSL::TLSXXX constants and min_version=/max_version= methods
              tls_versions_map = {
                TLSv1: :'TLSv1',
                TLSv1_1: :'TLSv1_1',
                TLSv1_2: :'TLSv1_2',
              }
              min_max_available = false
            end

            context = OpenSSL::SSL::SSLContext.new()
            if min_max_available && @ssl_min_version && @ssl_max_version
              context.min_version = tls_versions_map[@ssl_min_version] || @ssl_min_version
              context.max_version = tls_versions_map[@ssl_max_version] || @ssl_max_version
            else
              context.ssl_version = tls_versions_map[@ssl_method] || @ssl_method
            end
            context.ca_file = @ca_file if @ca_file
            context.verify_mode = @verify_mode if @verify_mode
            context.cert = OpenSSL::X509::Certificate.new(File.open(@client_cert) { |f| f.read }) if @client_cert
            context.key = OpenSSL::PKey::RSA.new(File.open(@client_cert_key) { |f| f.read }, @client_cert_key_pass) if @client_cert_key

            @socket = OpenSSL::SSL::SSLSocket.new(@tcp_socket, context)
            if @timeout && @timeout >= 0
              Timeout.timeout(@timeout) do
                @socket.connect
              end
            else
              @socket.connect
            end
            if @verify_mode != OpenSSL::SSL::VERIFY_NONE
              @socket.post_connection_check(@remote_hostname)
              raise "verification error" if @socket.verify_result != OpenSSL::X509::V_OK
            end
          else
            @socket = @tcp_socket
          end
        rescue
          if connect_retry_count < connect_retry_limit
            sleep connect_retry_interval
            connect_retry_count += 1
            retry
          else
            raise
          end
        end
      end
    end

    def send_msg(payload)
      if @tls
        method = :syswrite
      elsif @timeout && @timeout >= 0
        method = :write_nonblock
      else
        method = :write
      end

      retry_limit = @retry_limit.to_i
      retry_interval = @retry_interval.to_f
      retry_count = 0

      payload << "\n"
      payload.force_encoding(Encoding::ASCII_8BIT)
      payload_size = payload.bytesize

      until payload_size <= 0
        start = get_time
        begin
          result = @mutex.synchronize do
            if @tls && @timeout && @timeout >= 0
              Timeout.timeout(@timeout) do
                @socket.__send__(method, payload)
              end
            else
              @socket.__send__(method, payload)
            end
          end
          payload_size -= result
          payload.slice!(0, result) if payload_size > 0
        rescue IO::WaitReadable
          timeout_wait = @timeout - (get_time - start)
          retry if IO.select([@socket], nil, nil, timeout_wait)

          raise NonBlockingTimeout if @timeout_exception
          break
        rescue IO::WaitWritable
          timeout_wait = @timeout - (get_time - start)
          retry if IO.select(nil, [@socket], nil, timeout_wait)

          raise NonBlockingTimeout if @timeout_exception
          break
        rescue
          if retry_count < retry_limit
            sleep retry_interval
            retry_count += 1
            retry_interval *= 2 if @exponential_backoff
            connect
            retry
          else
            raise
          end
        end
      end
    end

    POSIX_CLOCK =
      if defined?(Process::CLOCK_MONOTONIC_COARSE)
        Process::CLOCK_MONOTONIC_COARSE
      elsif defined?(Process::CLOCK_MONOTONIC)
        Process::CLOCK_MONOTONIC
      elsif defined?(Process::CLOCK_REALTIME_COARSE)
        Process::CLOCK_REALTIME_COARSE
      elsif defined?(Process::CLOCK_REALTIME)
        Process::CLOCK_REALTIME
      end

    def get_time
      if POSIX_CLOCK
        Process.clock_gettime(POSIX_CLOCK)
      else
        Time.now.to_f
      end
    end
  end
end
