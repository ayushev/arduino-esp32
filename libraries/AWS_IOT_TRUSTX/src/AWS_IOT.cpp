/***************************************************************************************************
                                    ExploreEmbedded Copyright Notice    
****************************************************************************************************
 * File:   AWS_IOT.cpp
 * Version: 1.0
 * Author: ExploreEmbedded
 * Website: http://www.exploreembedded.com/wiki
 * Description: ESP32  Arduino library for AWS IOT.
 
This code has been developed and tested on ExploreEmbedded boards.  
We strongly believe that the library works on any of development boards for respective controllers. 
Check this link http://www.exploreembedded.com/wiki for awesome tutorials on 8051,PIC,AVR,ARM,Robotics,RTOS,IOT.
ExploreEmbedded invests substantial time and effort developing open source HW and SW tools, to support consider buying the ExploreEmbedded boards.
 
The ExploreEmbedded libraries and examples are licensed under the terms of the new-bsd license(two-clause bsd license).
See also: http://www.opensource.org/licenses/bsd-license.php

EXPLOREEMBEDDED DISCLAIMS ANY KIND OF HARDWARE FAILURE RESULTING OUT OF USAGE OF LIBRARIES, DIRECTLY OR
INDIRECTLY. FILES MAY BE SUBJECT TO CHANGE WITHOUT PRIOR NOTICE. THE REVISION HISTORY CONTAINS THE INFORMATION 
RELATED TO UPDATES.
 

Permission to use, copy, modify, and distribute this software and its documentation for any purpose
and without fee is hereby granted, provided that this copyright notices appear in all copies 
and that both those copyright notices and this permission notice appear in supporting documentation.
**************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "AWS_IOT.h"
#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"

#include "aws_iot_mqtt_client.h"
#include "aws_iot_mqtt_client_interface.h"


#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "driver/sdmmc_host.h"

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/ifx_i2c/ifx_i2c.h"
#include "optiga/pal/pal.h"
#include "optiga/pal/pal_os_event.h"
 
static const char *TAG = "AWS_IOT";
char AWS_IOT_HOST_ADDRESS[128];

char cPayload[512];
AWS_IoT_Client client;
IoT_Publish_Message_Params paramsQOS0;
pSubCallBackHandler_t subApplCallBackHandler = 0;

optiga_comms_t optiga_comms = {(void*)&ifx_i2c_context_0, NULL, NULL, 0};
static host_lib_status_t optiga_comms_status;



/* CA Root certificate, device ("Thing") certificate and device
 * ("Thing") key.

   "Embedded Certs" are stored in the file aws_iot_certificates.c as arrays
*/
extern const char aws_root_ca_pem[];
extern const char certificate_pem_crt[];
extern const char private_pem_key[];



void aws_iot_task(void *param);

static void read_ifx_cert(void)
{
		uint8_t ifx_cert_hex[512];
		uint16_t  ifx_cert_hex_len = sizeof(ifx_cert_hex);
		size_t  ifx_cert_b64_len = 0;
		uint8_t ifx_cert_b64_temp[768];
		uint16_t offset_to_read = 0;
		uint16_t offset_to_write = 0;
		uint16_t size_to_copy = 0;
		ESP_ERROR_CHECK( optiga_util_read_data(eDEVICE_PUBKEY_CERT_PRJSPC_1, 0, ifx_cert_hex, &ifx_cert_hex_len) );
		mbedtls_base64_encode((unsigned char *)ifx_cert_b64_temp, sizeof(ifx_cert_b64_temp),
								&ifx_cert_b64_len,
								ifx_cert_hex + 9, ifx_cert_hex_len - 9);

	//	esp_log_buffer_hex("main", ifx_cert_b64_temp, ifx_cert_b64_len);

		memcpy(certificate_pem_crt, "-----BEGIN CERTIFICATE-----\n", 28);
		offset_to_write += 28;

		//Properly copy certificate and format it as pkcs expects
		for (offset_to_read = 0; offset_to_read < ifx_cert_b64_len;)
		{
			// The last block of data usually is less than 64, thus we need to find the leftover
			if ((offset_to_read + 64) >= ifx_cert_b64_len)
				size_to_copy = ifx_cert_b64_len - offset_to_read;
			else
				size_to_copy = 64;
			memcpy(certificate_pem_crt + offset_to_write, ifx_cert_b64_temp + offset_to_read, size_to_copy);
			offset_to_write += size_to_copy;
			offset_to_read += size_to_copy;
			certificate_pem_crt[offset_to_write] = '\n';
			offset_to_write++;
		}

		memcpy(certificate_pem_crt + offset_to_write, "-----END CERTIFICATE-----\n\0", 27);

		ESP_LOGI("main", "End Device Certificate:\n\r %s", certificate_pem_crt);
}

static void optiga_comms_event_handler(void* upper_layer_ctx, host_lib_status_t event)
{
    optiga_comms_status = event;
}

static int32_t optiga_init(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	do
	{
		if (pal_os_event_init() == PAL_STATUS_FAILURE)
		{
			return OPTIGA_COMMS_BUSY;
		}
	
		// OPTIGA Initialisation phase
		//Invoke optiga_comms_open to initialize the IFX I2C Protocol and security chip
		optiga_comms_status = OPTIGA_COMMS_BUSY;
		optiga_comms.upper_layer_handler = optiga_comms_event_handler;
		status = optiga_comms_open(&optiga_comms);
		if(E_COMMS_SUCCESS != status)
		{
			configPRINTF( ("Failure: optiga_comms_open(): 0x%04X\n\r", status) );
			break;
		}

		//Wait until IFX I2C initialization is complete
		while(optiga_comms_status == OPTIGA_COMMS_BUSY)
		{
			pal_os_timer_delay_in_milliseconds(1);
		}
		
		if((OPTIGA_COMMS_SUCCESS != status) || (optiga_comms_status == OPTIGA_COMMS_ERROR))
		{
			configPRINTF( ("Failure: optiga_comms_status(): status = 0x%04X, comms_status = 0x%04X\n\r", status, optiga_comms_status) );
			break;
		}

		status = optiga_util_open_application(&optiga_comms);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			configPRINTF( ("Failure: CmdLib_OpenApplication(): 0x%04X\n\r", status) );
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while(0);

	return status;
}

void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
        IoT_Publish_Message_Params *params, void *pData) 
{
    if(subApplCallBackHandler != 0) //User call back if configured
    subApplCallBackHandler(topicName,params->payloadLen,(char *)params->payload);
}



void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data)
{
    ESP_LOGW(TAG, "MQTT Disconnect");
    IoT_Error_t rc = FAILURE;

    if(NULL == pClient) 
    {
        return;
    }

    if(aws_iot_is_autoreconnect_enabled(pClient)) {
        ESP_LOGI(TAG, "Auto Reconnect is enabled, Reconnecting attempt will start now");
    } 
    else
    {
        ESP_LOGW(TAG, "Auto Reconnect not enabled. Starting manual reconnect...");
      //  rc = aws_iot_mqtt_attempt_reconnect(pClient);
        if(NETWORK_RECONNECTED == rc) {
            ESP_LOGW(TAG, "Manual Reconnect Successful");
        } 
        else {
            ESP_LOGW(TAG, "Manual Reconnect Failed - %d", rc);
        }
    }
}

int AWS_IOT::connect(char *hostAddress, char *clientID)
{
    const size_t stack_size = 36*1024;
    
    strcpy(AWS_IOT_HOST_ADDRESS,hostAddress);
    IoT_Error_t rc = FAILURE;


    IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
    IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;
    
	printf("Init OPTIGA Trust X\r\n");
	optiga_init();
	read_ifx_cert();
	
    ESP_LOGI(TAG, "AWS IoT SDK Version %d.%d.%d-%s", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

    mqttInitParams.enableAutoReconnect = false; // We enable this later below
    mqttInitParams.pHostURL = AWS_IOT_HOST_ADDRESS;
    mqttInitParams.port = CONFIG_AWS_IOT_MQTT_PORT;


    mqttInitParams.pRootCALocation = (const char *)aws_root_ca_pem;
    mqttInitParams.pDeviceCertLocation = (const char *)certificate_pem_crt;
    mqttInitParams.pDevicePrivateKeyLocation = (const char *)private_pem_key;


    mqttInitParams.mqttCommandTimeout_ms = 20000;
    mqttInitParams.tlsHandshakeTimeout_ms = 5000;
    mqttInitParams.isSSLHostnameVerify = true;
    mqttInitParams.disconnectHandler = disconnectCallbackHandler;
    mqttInitParams.disconnectHandlerData = NULL;


    rc = aws_iot_mqtt_init(&client, &mqttInitParams);
   
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "aws_iot_mqtt_init returned error : %d ", rc);
        return rc; //abort();
    }

    connectParams.keepAliveIntervalInSec = 10;
    connectParams.isCleanSession = true;
    connectParams.MQTTVersion = MQTT_3_1_1;
    /* Client ID is set in the menuconfig of the example */
    connectParams.pClientID = clientID;
    connectParams.clientIDLen = (uint16_t) strlen(clientID);
    connectParams.isWillMsgPresent = false;

    ESP_LOGI(TAG, "Connecting to AWS...");
    
    do {
        rc = aws_iot_mqtt_connect(&client, &connectParams);
        
        if(SUCCESS != rc) {
            ESP_LOGE(TAG, "Error(%d) connecting to %s:%d, \n\rTrying to reconnect", rc, mqttInitParams.pHostURL, mqttInitParams.port);
            
        }
        
    } while(SUCCESS != rc);
  

    /*
     * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
     *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
     *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
     */
  /*  rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "Unable to set Auto Reconnect to true - %d", rc);
        abort();
    } */   
    
    if(rc == SUCCESS)
    xTaskCreatePinnedToCore(&aws_iot_task, "aws_iot_task", stack_size, NULL, 5, NULL, 1);

    return rc;
}


int AWS_IOT::publish(char *pubtopic,char *pubPayLoad)
{
    IoT_Error_t rc;

    paramsQOS0.qos = QOS0;
    paramsQOS0.payload = (void *) pubPayLoad;
    paramsQOS0.isRetained = 0;

    paramsQOS0.payloadLen = strlen(pubPayLoad);
    rc = aws_iot_mqtt_publish(&client, pubtopic, strlen(pubtopic), &paramsQOS0);
    
    return rc;  
}



int AWS_IOT::subscribe(char *subTopic, pSubCallBackHandler_t pSubCallBackHandler)
{
    IoT_Error_t rc;
    
    subApplCallBackHandler = pSubCallBackHandler;

    ESP_LOGI(TAG, "Subscribing...");
    rc = aws_iot_mqtt_subscribe(&client, subTopic, strlen(subTopic), QOS0, iot_subscribe_callback_handler, NULL);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "Error subscribing : %d ", rc);
        return rc;
    }
    ESP_LOGI(TAG, "Subscribing... Successful");
    
    return rc;
}




void aws_iot_task(void *param) {

IoT_Error_t rc = SUCCESS;

    while(1)
    {
        //Max time the yield function will wait for read messages
        rc = aws_iot_mqtt_yield(&client, 200);
        
        if(NETWORK_ATTEMPTING_RECONNECT == rc)
        {
            // If the client is attempting to reconnect we will skip the rest of the loop.
            continue;
        }

        
        vTaskDelay(1000 / portTICK_RATE_MS);
    }
}
