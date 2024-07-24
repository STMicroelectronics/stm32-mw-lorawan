/*!
 * \file      LmhpDataDistribution.h
 *
 * \brief     Function prototypes for LoRaMac Data distribution agent
 *
 * \copyright Revised BSD License, see section \ref LICENSE.
 *
 */
#ifndef __LMHP_DATA_DISTRIBUTION_H__
#define __LMHP_DATA_DISTRIBUTION_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "LmHandlerTypes.h"
#include "LmhPackage.h"
  
/* Exported defines ----------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported types ------------------------------------------------------------*/
/* External variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
LmHandlerErrorStatus_t LmhpDataDistributionInit(void);

LmHandlerErrorStatus_t LmhpDataDistributionPackageRegister(uint8_t id, LmhPackage_t **package);

#ifdef __cplusplus
}
#endif

#endif // __LMHP_DATA_DISTRIBUTION_H__