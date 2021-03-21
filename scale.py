import json

import boto3
import botocore
from datetime import datetime

ec2_client = boto3.client('ec2')
asg_client = boto3.client('autoscaling')


def lambda_handler(event, context):
    if event["detail-type"] == "EC2 Instance-launch Lifecycle Action":
        instance_id = event["detail"]["EC2InstanceId"]
        disable_src_dst(instance_id)
        mng_subnet_id = get_mng_subnet_id(instance_id)
        interface_id = create_interface(mng_subnet_id, event, instance_id)
        attachment = attach_interface(interface_id, instance_id)
        if interface_id and not attachment:
            log("Removing network interface {} after attachment failed.".format(interface_id))
            delete_interface(interface_id,instance_id)

        try:
            asg_client.complete_lifecycle_action(
                LifecycleHookName=event['detail']['LifecycleHookName'],
                AutoScalingGroupName=event['detail']['AutoScalingGroupName'],
                LifecycleActionToken=event['detail']['LifecycleActionToken'],
                LifecycleActionResult='CONTINUE'
            )

            if attachment:
                log('{"Error": "0"}')
            else:
                log('{"Error": "1"}')
        except botocore.exceptions.ClientError as e:
            log("Error completing life cycle hook for instance {}: {}".format(instance_id, e.response['Error']['Code']))
            log('{"Error": "1"}')
    elif event["detail-type"] == "EC2 Instance-terminate Lifecycle Action":
        instance_id = event["detail"]["EC2InstanceId"]
        terminate_dp(instance_id)
        


def get_mng_subnet_id(instance_id):
    try:
        result = ec2_client.describe_instances(InstanceIds=[instance_id])
        vpc_id = result['Reservations'][0]['Instances'][0]['VpcId']
        log("VPC ID of current instance: {} ".format(vpc_id))
        instancezone= result['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
        log("Zone of data interface: {} ".format(instancezone))
        found = 0
        mng_subnet_id = []
        mng_subnet_id = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]},{'Name': 'tag:Type', 'Values': ['MNG']},])['Subnets']
        if len(mng_subnet_id) > 0:
            for subnet in mng_subnet_id:
                azones= subnet["AvailabilityZone"]
                log("Found MNG TAG in the following zone: {}".format(azones))
                if azones ==instancezone:
                    mng_subnet_id = subnet['SubnetId']
                    found = 1
                    log("[Success]: Found the following managment subnet ID with a tag in the same VPC and Zone as the DATA interface: {} ".format(mng_subnet_id))
                    break
            if found == 0:
                log("[ERROR]: Unable to find MNG TAG in the same VPC and Zone")
        else:
            log("Unable to find the managment subnet by TAG: {}".format(mng_subnet_id))
    except botocore.exceptions.ClientError as e:
        log("Error finding managmnet subnet {} ".format(e.response['Error']['Code']))
        mng_subnet_id = None
    return mng_subnet_id


def disable_src_dst(instance_id):
    try:
        interfaces_dict = ec2_client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'attachment.instance-id',
                    'Values': [instance_id]

                },
                {
                    'Name': 'attachment.device-index',
                    'Values': ['0']

                }]
        )
        interface_id = (interfaces_dict.get('NetworkInterfaces')[0]).get('NetworkInterfaceId')
        ec2_client.modify_network_interface_attribute(
            SourceDestCheck={
                'Value': False,
            },
            NetworkInterfaceId=interface_id,
        )
        log("Successfully disabled the src dst check for interface: {} ".format(interface_id))

    except:
        log("Unable to disabled the src dst check for the instance: {} ".format(instance_id))


def create_interface(subnet_id, event, instance_id):
    network_interface_id = None

    if subnet_id:
        try:
            asg_response = asg_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[event['detail']['AutoScalingGroupName']]
            )
            string_response = asg_response["AutoScalingGroups"][0]["VPCZoneIdentifier"]
            list_response = string_response.split(",");
            result = ec2_client.describe_instances(InstanceIds=[instance_id])
            reservations = result['Reservations']
            security_groups_in_use = []
            for i in reservations:
                for j in i['Instances']:
                    for m in j['NetworkInterfaces']:
                        for n in m['Groups']:
                            security_groups_in_use.append(n['GroupId'])
            log("Creating managment interface with the following secuirty group: {}".format(security_groups_in_use))
            network_interface = ec2_client.create_network_interface(SubnetId=subnet_id, Groups=[security_groups_in_use][0])
            network_interface_id = network_interface['NetworkInterface']['NetworkInterfaceId']
            
            log("Created network interface: {}".format(network_interface_id))
        except botocore.exceptions.ClientError as e:
            log("Error creating network interface: {}".format(e.response['Error']['Code']))

    return network_interface_id


def attach_interface(network_interface_id, instance_id):
    attachment = None

    if network_interface_id and instance_id:
        try:
            attach_interface = ec2_client.attach_network_interface(
                NetworkInterfaceId=network_interface_id,
                InstanceId=instance_id,
                DeviceIndex=1
            )
            attachment = attach_interface['AttachmentId']
            ec2_client.modify_network_interface_attribute(
                Attachment={
                    'AttachmentId': attachment,
                    'DeleteOnTermination': True,
                    
                },
                NetworkInterfaceId=network_interface_id,
                )
            log("Created network attachment: {}".format(attachment))

        except botocore.exceptions.ClientError as e:
            log("Error attaching network interface: {}".format(e.response['Error']['Code']))
    err = allocate_and_attach_eip(network_interface_id)
    if err == 'false':
        log('{"[ERROR] allocate and attach failed"}')
        terminate('false', message)
        return
    else:
        log('{"[INFO] allocate and attach successful"}')
        dpMgmtIp = err.get('PublicIp')
        if dpMgmtIp == None:
            log('{"[ERROR] dpMgmtIp is None"}')
            terminate('false', message)
            return
        else:
            log("dpMgmtIp is: {} ".format(dpMgmtIp))
    return attachment

def allocate_and_attach_eip(Id):
    eip_address_dict = ec2_client.describe_addresses()
    log("eipaddressdict: {}".format(eip_address_dict))
    eip = allocateEip()
    err = associateAddress(eip['AllocationId'], Id)
    log("[INFO]: does err have an allocationID ".format(err))
    if err == 'false':
        log("Successfully disabled the src dst check for interface: {} ".format(err))
        return 'false'
    log("[INFO]: what is the EIP: {} ".format(eip))
    return eip
    
def getUnassociatedAddress(eip_list):
    for eip_iter in eip_list:
        #is the public ip address associated with an instance id, if so don't use it
        if "InstanceId" not in eip_iter:
            address = eip_iter['PublicIp']
            if address:
                return  eip_iter #Means we found an address, so return the class
    return None


def allocateEip():
    try:
        eip = ec2_client.allocate_address(Domain='vpc')
    except Exception as e:
        log("Error Unable to allocate elastic IP  {} ".format(e.response['Error']['Code']))
        return 'false'
    else:
        #Associate eip with Instance ID
        log("[INFO]: Allocated elastic IP ")
        return eip

def associateAddress(AllocId, nifId):
    try:
        ec2_client.associate_address(AllocationId=AllocId, NetworkInterfaceId=nifId)
    except Exception as e:
        log("Error Unable to allocate elastic IP  {} ".format(e.response['Error']['Code']))
        return 'false'
    else:
        return 'true'

def delete_interface(network_interface_id,instance_id):
    try:
        public_ip_list = ec2_client.describe_addresses(
            Filters=[
                {
                    'Name': 'instance-id',
                    'Values': [instance_id]

                }]
        )
    except:
        log("[ERROR]: Error getting public ip addresses")
        return
    for public_ip in public_ip_list.get('Addresses'):
        try:
            ec2_client.disassociate_address(AssociationId=public_ip.get('AssociationId'))
        except Exception as e:
            log("[ERROR]: Error whilst disassociating elastic IP addresses")
            log("[RESPONSE]: {}".format(e))
            return

        try:
            ec2_client.release_address(AllocationId=public_ip.get('AllocationId'))
        except Exception as e:
            log("[ERROR]: Error whilst releasing elastic IP addresses")
            log("[RESPONSE]: {}".format(e))
        return
    try:
        ec2_client.delete_network_interface(
            NetworkInterfaceId=network_interface_id
        )
        return True

    except botocore.exceptions.ClientError as e:
        log("Error deleting interface {}: {}".format(network_interface_id, e.response['Error']['Code']))

def terminate_dp(instance_id):
    while True:
        try:
            interfaces_list = ec2_client.describe_network_interfaces(
                Filters=[
                {
                    'Name': 'attachment.instance-id',
                    'Values': [instance_id]
                }]
            )
        except:
            log("[ERROR]: Describe Interfaces problem")
            terminate('false', message)
            return
        else:
            log("[INFO] Found some interfaces")
            break

    if not interfaces_list:
        log("[ERROR]: No interfaces listed for instance-id {}]:".format(instance_id))
        terminate('false', message)
        return

    for interface in interfaces_list.get('NetworkInterfaces'):
        log("[Interface]: {}".format(interface))
        if interface.get('Attachment').get('DeviceIndex') == 1:
            dpMgmtIp = interface.get('Association').get('PublicIp')
            continue
        try:
            public_ip_list = ec2_client.describe_addresses(
                Filters=[
                    {
                        'Name': 'instance-id',
                        'Values': [instance_id]
                        
                    }]
                    )
        except:
            log("[ERROR]: Error getting public ip addresses")
            terminate('false', message)
            return

        for public_ip in public_ip_list.get('Addresses'):
            try:
                ec2_client.disassociate_address(AssociationId=public_ip.get('AssociationId'))
            except Exception as e:
                log("[ERROR]: Error whilst disassociating elastic IP addresses")
                log("[RESPONSE]: {}".format(e))
                terminate('false', message)
                return
    
            try:
                ec2_client.release_address(AllocationId=public_ip.get('AllocationId'))
            except Exception as e:
                log("[ERROR]: Error whilst releasing elastic IP addresses")
                log("[RESPONSE]: {}".format(e))
                terminate('false', message)
                return

def terminate(success, asg_message):
    global instanceId

    if asg_message == None:
        return 
    else:

        if (success == 'false'):
            logging.error("[ERROR]: Lambda function reporting failure to AutoScaling with error:\n")
            result = "ABANDON"
        else:
            logger.info("[INFO]: Lambda function reporting success to AutoScaling.")
            result = "CONTINUE"

        #call autoscaling
        asg.complete_lifecycle_action(
            AutoScalingGroupName = asg_message['AutoScalingGroupName'],
            LifecycleHookName = asg_message['LifecycleHookName'],
            LifecycleActionToken = asg_message['LifecycleActionToken'],
            InstanceId = instanceId,
            LifecycleActionResult = result)
        return
    
def log(message):
    print('{}Z {}'.format(datetime.utcnow().isoformat(), message))
