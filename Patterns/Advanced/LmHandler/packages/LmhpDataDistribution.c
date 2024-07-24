/*!
 * \file      LmhpDataDistribution.c
 *
 * \brief     Implements the Data Distribution Agent 
 *
 * \copyright Revised BSD License, see section \ref LICENSE.
 *
 */

/* Includes ------------------------------------------------------------------*/
#include "LmhpDataDistribution.h"
#include "LmhpClockSync.h"
#include "LmhpRemoteMcastSetup.h"
#include "LmhpFragmentation.h"
#include "LmHandler.h"
#include "mw_log_conf.h"

#include "flash_if.h"
#include "se_def_metadata.h"
#if defined (__ICCARM__) || defined(__GNUC__)
#include "mapping_export.h"         /* to access to the definition of REGION_SLOT_1_START*/
#elif defined(__CC_ARM)
#include "mapping_fwimg.h"
#endif

/* Private typedef -----------------------------------------------------------*/
/*structure containing values related to the management of multi-images in Flash*/
typedef struct
{
  uint32_t  MaxSizeInBytes;        /*!< The maximum allowed size for the FwImage in User Flash (in Bytes) */
  uint32_t  DownloadAddr;          /*!< The download address for the FwImage in UserFlash */
  uint32_t  ImageOffsetInBytes;    /*!< Image write starts at this offset */
  uint32_t  ExecutionAddr;         /*!< The execution address for the FwImage in UserFlash */
} FwImageFlashTypeDef;

/* Private define ------------------------------------------------------------*/
/*!
 * Defines the maximum size for the buffer receiving the fragmentation result.
 *
 * \remark By default FragDecoder.h defines:
 *         \ref FRAG_MAX_NB   313
 *         \ref FRAG_MAX_SIZE 216
 *
 *         In interop test mode will be
 *         \ref FRAG_MAX_NB   21
 *         \ref FRAG_MAX_SIZE 50
 *
 *         FileSize = FRAG_MAX_NB * FRAG_MAX_SIZE
 *
 *         If bigger file size is to be received or is fragmented differently
 *         one must update those parameters.
 *
 * \remark  Memory allocation is done at compile time. Several options have to be foreseen
 *          in order to optimize the memory. Will depend of the Memory management used
 *          Could be Dynamic allocation --> malloc method
 *          Variable Length Array --> VLA method
 *          pseudo dynamic allocation --> memory pool method
 *          Other option :
 *          In place of using the caching memory method we can foreseen to have a direct
 *          flash memory copy. This solution will depend of the SBSFU constraint
 *
 */
#define UNFRAGMENTED_DATA_SIZE                      ( FRAG_MAX_NB * FRAG_MAX_SIZE )

/*starting offset to add to the  first address */
#define SFU_IMG_IMAGE_OFFSET ((uint32_t)512U)

/*size of header to write in Swap sector to trigger installation*/
#define INSTALLED_LENGTH  ((uint32_t)512U)

#define SFU_IMG_SWAP_REGION_SIZE                    ((uint32_t)(REGION_SWAP_END - REGION_SWAP_START + 1U))

#define SFU_IMG_SWAP_REGION_BEGIN_VALUE             ((uint32_t)REGION_SWAP_START)

#define SFU_IMG_SLOT_DWL_REGION_BEGIN_VALUE         ((uint32_t)REGION_SLOT_1_START)

#define SFU_IMG_SLOT_DWL_REGION_SIZE                ((uint32_t)(REGION_SLOT_1_END - REGION_SLOT_1_START + 1U))

/* Private macro -------------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/**
  * @brief  Write `data` buffer of `size` starting at address `addr`
  * @param  addr Address start index to write to.
  * @param  data Data buffer to be written.
  * @param  size Size of data buffer to be written.
  * @retval status Write operation status [0: Success, -1 Fail]
  */  
static uint8_t FragDecoderWrite(uint32_t addr, uint8_t *data, uint32_t size);

/**
  * @brief  Reads `data` buffer of `size` starting at address `addr`
  * @param  addr Address start index to read from.
  * @param  data Data buffer to be read.
  * @param  size Size of data buffer to be read.
  * @retval status Read operation status [0: Success, -1 Fail]
  */  
static uint8_t FragDecoderRead(uint32_t addr, uint8_t *data, uint32_t size);

/**
  * @brief  Callback to get the current progress status of the fragmentation session
  * @param  fragCounter fragment counter
  * @param  fragNb number of fragments
  * @param  fragSize size of fragments
  * @param  fragNbLost number of lost fragments
  * @retval None
  */  
static void OnFragProgress(uint16_t fragCounter, uint16_t fragNb, uint8_t fragSize, uint16_t fragNbLost);

/**
  * @brief  Callback to notify when the fragmentation session is finished
  * @param  status status of the fragmentation process
  * @param  size size of the fragmented data block
  * @retval None
  */
static void OnFragDone(int32_t status, uint32_t size);

/**
  * @brief  Run FW Update process.
  * @param  None
  * @retval None
  */
static void FwUpdateAgentRun(void);

/**
  * @brief  Provide the area descriptor to write a FW image in Flash.
  *         This function is used by the User Application to know where to store
  *          a new Firmware Image before asking for its installation.
  * @param  pArea pointer to area descriptor
  * @retval HAL_OK if successful, otherwise HAL_ERROR
  */
static uint32_t FwUpdateAgentGetDownloadAreaInfo(FwImageFlashTypeDef *pArea);

/**
  * @brief  Write in Flash the next header image to install.
  *         This function is used by the User Application to request a Firmware installation (at next reboot).
  * @param  fw_header FW header of the FW to be installed
  * @retval HAL_OK if successful, otherwise HAL_ERROR
  */
static uint32_t FwUpdateAgentInstallAtNextReset(uint8_t *fw_header);

/* Private variables ---------------------------------------------------------*/
static LmhpFragmentationParams_t FragmentationParams =
{
  .DecoderCallbacks =
  {
    .FragDecoderWrite = FragDecoderWrite,
    .FragDecoderRead = FragDecoderRead,
  },
  .OnProgress = OnFragProgress,
  .OnDone = OnFragDone
};

/*
 * Indicates if the file transfer is done
 */
static volatile bool IsFileTransferDone = false;

/* Exported functions ---------------------------------------------------------*/
LmHandlerErrorStatus_t LmhpDataDistributionInit(void)
{
  if ( LmHandlerPackageRegister( PACKAGE_ID_CLOCK_SYNC, NULL) != LORAMAC_HANDLER_SUCCESS )
  {
    return LORAMAC_HANDLER_ERROR;
  }
  else if ( LmHandlerPackageRegister( PACKAGE_ID_REMOTE_MCAST_SETUP, NULL ) != LORAMAC_HANDLER_SUCCESS )
  {
    return LORAMAC_HANDLER_ERROR;
  }
  else if ( LmHandlerPackageRegister( PACKAGE_ID_FRAGMENTATION, &FragmentationParams ) != LORAMAC_HANDLER_SUCCESS )
  {
    return LORAMAC_HANDLER_ERROR;
  }

  return LORAMAC_HANDLER_SUCCESS;
}

LmHandlerErrorStatus_t LmhpDataDistributionPackageRegister(uint8_t id, LmhPackage_t **package)
{
  if( package == NULL )
  {
    return LORAMAC_HANDLER_ERROR;
  }
  switch( id )
  {
  case PACKAGE_ID_CLOCK_SYNC:
    {
      *package = LmphClockSyncPackageFactory( );
      break;
    }
  case PACKAGE_ID_REMOTE_MCAST_SETUP:
    {
      *package = LmhpRemoteMcastSetupPackageFactory( );
      break;
    }
  case PACKAGE_ID_FRAGMENTATION:
    {
      *package = LmhpFragmentationPackageFactory( );
      break;
    }
  }

  return LORAMAC_HANDLER_SUCCESS;
}

/* Private  functions ---------------------------------------------------------*/
static uint8_t FragDecoderWrite(uint32_t addr, uint8_t *data, uint32_t size)
{
  if (size >= UNFRAGMENTED_DATA_SIZE)
  {
    return (uint8_t) - 1; /* Fail */
  }

  if (FLASH_Write((void *)addr, (uint8_t *)data, size) != HAL_OK)
  {
    return -1;
  }

  return 0; // Success
}

static uint8_t FragDecoderRead(uint32_t addr, uint8_t *data, uint32_t size)
{
  if (size >= UNFRAGMENTED_DATA_SIZE)
  {
    return (uint8_t) - 1; /* Fail */
  }

  FLASH_Read((void *)addr, data, size);

  return 0; // Success
}

static void OnFragProgress(uint16_t fragCounter, uint16_t fragNb, uint8_t fragSize, uint16_t fragNbLost)
{
  MW_LOG(TS_OFF, VLEVEL_H, "\r\n....... FRAG_DECODER in Progress .......\r\n");
  MW_LOG(TS_OFF, VLEVEL_H, "RECEIVED    : %5d / %5d Fragments\r\n", fragCounter, fragNb);
  MW_LOG(TS_OFF, VLEVEL_H, "              %5d / %5d Bytes\r\n", fragCounter * fragSize, fragNb * fragSize);
  MW_LOG(TS_OFF, VLEVEL_H, "LOST        :       %7d Fragments\r\n\r\n", fragNbLost);
}

static void OnFragDone(int32_t status, uint32_t size)
{
  IsFileTransferDone = true;

  /*Do a request to Run the Secure boot - The file is already in flash*/
  FwUpdateAgentRun();

  MW_LOG(TS_OFF, VLEVEL_H, "\r\n....... FRAG_DECODER Finished .......\r\n");
  MW_LOG(TS_OFF, VLEVEL_H, "STATUS      : %ld\r\n", status);
}

static void FwUpdateAgentRun(void)
{
  HAL_StatusTypeDef ret = HAL_ERROR;
  uint8_t  fw_header_input[SE_FW_HEADER_TOT_LEN];
  FwImageFlashTypeDef fw_image_dwl_area;

  /* Get Info about the download area */
  if (FwUpdateAgentGetDownloadAreaInfo(&fw_image_dwl_area) != HAL_ERROR)
  {
    /* Read header in slot 1 */
    memcpy((void *) fw_header_input, (void *) fw_image_dwl_area.DownloadAddr, sizeof(fw_header_input));

    /* Ask for installation at next reset */
    (void)FwUpdateAgentInstallAtNextReset((uint8_t *) fw_header_input);

    /* System Reboot*/
    MW_LOG(TS_OFF, VLEVEL_H, "  -- Image correctly downloaded - reboot\r\n\n");
    HAL_Delay(1000U);
    NVIC_SystemReset();
  }
  if (ret != HAL_OK)
  {
    MW_LOG(TS_OFF, VLEVEL_H, "  --  Operation Failed  \r\n");
  }
}

static uint32_t FwUpdateAgentGetDownloadAreaInfo(FwImageFlashTypeDef *pArea)
{
  uint32_t ret;
  if (pArea != NULL)
  {
    pArea->DownloadAddr = SFU_IMG_SLOT_DWL_REGION_BEGIN_VALUE;
    pArea->MaxSizeInBytes = (uint32_t)SFU_IMG_SLOT_DWL_REGION_SIZE;
    pArea->ImageOffsetInBytes = SFU_IMG_IMAGE_OFFSET;
    ret =  HAL_OK;
  }
  else
  {
    ret = HAL_ERROR;
  }
  return ret;
}

static uint32_t FwUpdateAgentInstallAtNextReset(uint8_t *fw_header)
{
  uint32_t ret = HAL_OK;
  uint8_t zero_buffer[INSTALLED_LENGTH - SE_FW_HEADER_TOT_LEN];
  
  if (fw_header == NULL)
  {
    return HAL_ERROR;
  }

  memset(zero_buffer, 0x00, sizeof(zero_buffer));
  ret = FLASH_Erase((void *) SFU_IMG_SWAP_REGION_BEGIN_VALUE, SFU_IMG_IMAGE_OFFSET);
  if (ret == HAL_OK)
  {
    ret = FLASH_Write((void *)SFU_IMG_SWAP_REGION_BEGIN_VALUE, fw_header, SE_FW_HEADER_TOT_LEN);
  }
  if (ret == HAL_OK)
  {
    ret = FLASH_Write((void *)(SFU_IMG_SWAP_REGION_BEGIN_VALUE + SE_FW_HEADER_TOT_LEN), (void *)zero_buffer, sizeof(zero_buffer));
  }
  return ret;
}
