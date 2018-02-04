# cleanup local directory
sudo rm -r ./dist/ ./build/
sudo rm -r /usr/local/lib/python2.7/dist-packages/ioc_regex*
sudo rm -r ./src/ioc_regex.egg-info/
find . -name \*.pyc -delete
