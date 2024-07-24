/**
  ******************************************************************************
  * @file    LmHandlerInfo.c
  * @author  MCD Application Team
  * @brief   To give info to the application about LoraWAN configuration
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2019 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
 ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "platform.h"
#include "lorawan_conf.h"
#include "LoRaMac.h"
#include "LmHandlerInfo.h"


/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static LmHandlerInfo_t lmHandlerInfo = {0, 0};

/* Private function prototypes -----------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported functions --------------------------------------------------------*/
/**
  * @brief initialises the LoraMacInfo capabilities table
  * @param none
  * @retval  none
  */
void LmHandlerInfo_Init(void)
{
  lmHandlerInfo.Region = 0;
  lmHandlerInfo.ClassB = 0;

#ifdef  REGION_AS923
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_AS923) ;
#endif
#ifdef  REGION_AU915
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_AU915) ;
#endif
#ifdef  REGION_CN470
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_CN470) ;
#endif
#ifdef  REGION_CN779
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_CN779) ;
#endif
#ifdef  REGION_EU433
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_EU433) ;
#endif
#ifdef  REGION_EU868
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_EU868) ;
#endif
#ifdef  REGION_KR920
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_KR920) ;
#endif
#ifdef  REGION_IN865
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_IN865) ;
#endif
#ifdef  REGION_US915
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_US915) ;
#endif
#ifdef  REGION_RU864
  lmHandlerInfo.Region |= (1 << LORAMAC_REGION_RU864) ;
#endif
  
  if (lmHandlerInfo.Region == 0)
  {
    APP_PRINTF("error: At leats one region shall be defined in the MW: check lorawan_conf.h \r\n");
    while(1) {} /* At leats one region shall be defined */
  }
  
#if ( LORAMAC_CLASSB_ENABLED == 1 )
  lmHandlerInfo.ClassB = 1;
#elif !defined (LORAMAC_CLASSB_ENABLED)
#error LORAMAC_CLASSB_ENABLED not defined ( shall be <0 or 1> )
#endif /* LORAMAC_CLASSB_ENABLED */

#if (!defined (LORAWAN_KMS) || (LORAWAN_KMS == 0)) 
  lmHandlerInfo.Kms = 0;
  lmHandlerInfo.ActivationMode = 3;
#else /* LORAWAN_KMS == 1 */
  lmHandlerInfo.Kms = 1;
  lmHandlerInfo.ActivationMode = ACTIVATION_BY_PERSONALISATION + OVER_THE_AIR_ACTIVATION<<1;
#endif
}

/**
  * @brief returns the pointer to the LoraMacInfo capabilities table
  * @param lmHandlerInfo pointer
  * @retval None
  */
LmHandlerInfo_t* LmHandlerInfo_GetPtr(void)
{
  return &lmHandlerInfo;
}

/* Private functions --------------------------------------------------------*/

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/

