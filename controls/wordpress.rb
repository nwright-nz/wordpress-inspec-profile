# encoding: utf-8

# copyright: 2018, Nigel Wright <nigel.wright@dimensiondata.com>

file_location = attribute('site_location', description: 'The location of the Wordpress files')
apache_conf = attribute('apache_conf_location', description: 'The location of the apache config file (must include config file name)')
approved_plugins = attribute('approved_plugins', description: 'The plugin whitelist')

title 'Wordpress Compliance Checks'

control 'wpress-01' do
  impact 0.8
  title 'Check .htaccess permissions'
  desc 'Ensure that .htaccess is as locked down as possible, set to 0400'
  describe.one do
    describe file(file_location + '/.htaccess') do
      its('mode') { should cmp '0400' }
    end
    describe file(file_location + '/.htaccess') do
      its('mode') { should cmp '0440' }
    end
    describe file(file_location + '/.htaccess') do
      its('mode') { should cmp '0444' }
    end
    describe file(file_location + '/.htaccess') do
      its('mode') { should cmp '0600' }
    end
    describe file(file_location + '/.htaccess') do
      its('mode') { should cmp '0640' }
    end
  end
end

control 'wpress-02' do
  impact 0.6
  title 'Ensure readme.html does not exist'
  desc 'readme.html can include the version number of wordpress, which assists in determining exploits'
  describe file(file_location + '/readme.html') do
    it { should_not exist }
  end
end

control 'wpress-03' do
  impact 0.7
  title 'Ensure license.txt does not exist'
  desc 'license.txt file cant include version related information of wordpress, which assists in determining exploits'
  describe file(file_location + '/license.txt') do
    it { should_not exist }
  end
end

control 'wpress-04' do
  impact 1.0
  title 'Ensure install.php file does not exist'
  desc 'Install.php file is only used for first run installs. Should no longer be present after installation has completed.'
  describe file(file_location + '/wp-admin/install.php') do
    it { should_not exist }
  end
end

control 'wpress-05' do
  impact 1.0
  title 'Check PHP version'
  desc 'PHP version should be up to date to avoid historical exploits'
  describe command('php -r "echo PHP_VERSION;"') do
    its('stdout') { should cmp >= '7.3.0' }
  end
end

control 'wpress-06' do
  impact 1.0
  title 'Check PHP modules'
  desc 'The only enabled modules should be a small subset ,as per the wordpress handbook'
  describe command('php -m').stdout.split do
    # Modules below from the wordpress handbook recommended list
    it { should include 'mysqli' }
    it { should include 'bcmath' }
    it { should include 'curl' }
    it { should include 'exif' }
    it { should include 'filter' }
    it { should include 'fileinfo' }
    it { should include 'imagick' }
    it { should include 'mysqli' }
    it { should include 'libsodium' }
    it { should include 'openssl' }
    it { should include 'xml' }
  end
end

control 'wpress-07' do
  impact 1.0
  title 'Check Wordpress Core version'
  desc 'Wordpress should be within one major version of latest to ensure historical exploits are not valid'
  describe command('echo $WORDPRESS_VERSION') do
    its('stdout.strip') { should cmp >= '5.2.0' }
  end
end

control 'wpress-08' do
  impact 1.0
  title 'Check wordpress db prefix'
  desc 'Wordpress database prefix should not be left as default wp_'
  describe file(file_location + '/wp-config.php'), :sensitive do
    its('content') { should_not match /wp_/ }
  end
end

control 'wpress-09' do
  impact 0.8
  title 'Check debug output is disabled'
  desc 'Ensures that the WP_DEBUG is disabled, to prevent leaking any sensitive information'
  describe file(file_location + '/wp-config.php'), :sensitive do
    its('content') { should match /\'WP_DEBUG\', false/ }
  end
end

control 'wpress-10' do
  impact 0.8
  title 'Check wp-config permissions'
  desc 'Ensure that wp-config is as locked down as possible, either 0400, 0440, 0600 or 0640'
  describe.one do
    describe file(file_location + '/wp-config.php') do
      its('mode') { should cmp '0400' }
    end
    describe file(file_location + '/wp-config.php') do
      its('mode') { should cmp '0440' }
    end
    describe file(file_location + '/wp-config.php') do
      its('mode') { should cmp '0640' }
    end
    describe file(file_location + '/wp-config.php') do
      its('mode') { should cmp '0600' }
    end
  end
end

control 'wpress-11' do
  impact 0.5
  title 'config-sample should not exist'
  desc 'Wp-config sample is not needed past the first run and should be removed'
  describe file(file_location + '/wp-config-sample.php') do
    it { should_not exist }
  end
end

control 'wpress-12' do
  impact 1.0
  title 'Directory listing should be disabled in .htaccess'
  desc 'Apache should NOT allow directory listing - this ensures sensitive files arent available to browse. This control checks both .htaccess and apache config'
  describe file(file_location + '/.htaccess'), :sensitive do
    its('content') { should match /IndexIgnore */ }
  end
end

control 'wpress-13' do
  impact 1.0
  title 'Directory listing should be disabled in apache config'
  describe file(apache_conf), :sensitive do
    it { should exist }
    its('content') { should_not match /Options Indexes/ }
  end
end

control 'wpress-14' do
  impact 1.0
  title 'Disable following of symlinks'
  describe file(apache_conf), :sensitive do
    its('content') { should_not match /FollowSymLinks/ }
  end
end

control 'wpress-15' do
  impact 1.0
  title 'Ensure up to date version of Apache'
  desc 'Make sure apache does not have any available updates'
  describe package('apache2') do
    its('version') { should cmp >= '2.4.25' }
  end
end

control 'wpress-16' do
  impact 0.8
  title 'Ensure that the uploads directory is writable'
  desc 'Uploads needs to be writable in order to store media for wordpress sites'
  describe directory(file_location + '/wp-content/uploads') do
    its('mode') { should cmp '0755' }
  end
end

control 'wpress-17' do
  impact 1.0
  title 'Make sure only approved plugins are installed'
  desc 'Plugins can cause many exploits and vulnerabilities to wordpress installations, this control checks that only whitelisted plugins are approved'
  describe command('wp plugin list --allow-root --path ' + file_location) do
    its('stdout') { should match /test/ }
  end
end