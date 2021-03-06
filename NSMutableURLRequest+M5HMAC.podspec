Pod::Spec.new do |s|
  s.name = 'NSMutableURLRequest+M5HMAC'
  s.summary = 'NSMutableURLRequest category to allow for easy HMAC signing.'
  s.version = '1.0.4'
  s.license = { :type => 'MIT', :file => 'LICENSE' }
  
  s.social_media_url = 'https://twitter.com/mhuusko5'
  s.authors = { 'Mathew Huusko V' => 'mhuusko5@gmail.com' }
  
  s.homepage =         'https://github.com/mhuusko5/NSMutableURLRequest-M5HMAC'
  s.source = { :git => 'https://github.com/mhuusko5/NSMutableURLRequest-M5HMAC.git', :tag => s.version.to_s }
  
  s.source_files = '*.{h,m}'
  s.requires_arc = true

  s.ios.deployment_target = '7.0'
  s.osx.deployment_target = '10.8'
  
  s.frameworks = 'Foundation'
end
