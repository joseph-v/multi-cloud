This is a CLI tool for connecting to OpenSDS multi-cloud client.

## How to use:

```bash

cd path/to/multi-cloud

export OPENSDS_ENDPOINT=http://192.168.20.158:50040
export OPENSDS_AUTH_STRATEGY=keystone
export OS_AUTH_URL=http://192.168.20.158/identity
export OS_USERNAME=admin
export OS_PASSWORD=opensds@123
export OS_TENANT_NAME=admin
export OS_PROJECT_NAME=admin
export OS_USER_DOMIN_ID=default

export MULTI_CLOUD_IP=192.168.20.158
export MICRO_SERVER_ADDRESS=:8089
export OS_AUTH_AUTHSTRATEGY=keystone

export OS_ACCESS_KEY=ZNRJARg7wkfm9wxzuIeD   # AK/SK Generated from dashboard

## Example Usage
go run mcctl/main.go --help
go run mcctl/main.go backend list
go run mcctl/main.go backend create '{"tenantId": "94b280022d0c4401bcf3b0ea85870519","userId": "558057c4256545bd8a307c37464003c9","name": "Azure-OpenSDS","type": "Azure Blob Storage","region": "East Asia","endpoint": "https://***.blob.core.windows.net/container","bucketName": "container","access": "***","security": "***"}'
go run mcctl/main.go bucket create bkt001 -l Azure-OpenSDS
echo "This is a test!" >test.txt
go run mcctl/main.go object upload bkt001 test.txt test.txt

go run mcctl/main.go object delete bkt001 test.txt
go run mcctl/main.go bucket delete bkt001
go run mcctl/main.go backend list
go run mcctl/main.go backend delete 5e69f110ce02e00001bec1b9
```