def configure_providers(vm, config)
    vm.provider "virtualbox" do |vb|
       vb.memory = config['memory']
       vb.cpus = config['cpus']
       vb.customize [
           'modifyvm', :id,
           '--nicpromisc3', "allow-all"
          ]
       vb.customize [
           "guestproperty", "set", :id,
           "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 10000
          ]
    end

    vm.provider 'parallels' do |vb|
       vb.memory = config['memory']
       vb.cpus = config['cpus']
       vb.customize ['set', :id, '--nested-virt', 'on']
    end

    vm.provider 'libvirt' do |vb|
       vb.memory = config['memory']
       vb.cpus = config['cpus']
       vb.nested = true
       vb.graphics_type = 'spice'
       vb.video_type = 'qxl'
       vb.suspend_mode = 'managedsave'
    end
end
