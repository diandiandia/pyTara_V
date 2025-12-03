from ai_assistant.deepseek_ai import DeepSeekAIAssistant
from typing import Dict, Any
from config import config as cfg


# Configure logging
from config.logging_config import setup_logger

# Configure logging
logger = setup_logger()


class TARAAnalyzer:
    def __init__(self):
        """
        Initialize the asset security attribute analyzer
        Args:
            ai_assistant (BaseAIAssistant): AI assistant instance for performing actual analysis
        """
        logger.info("Initializing TARAAnalyzer instance")
        self.ai_assistant = self.assistant_builder()
        self._system_prompt = "你现在是拥有丰富经验的ISO 21434 的汽车网络安全专家。当前 Item 是：自动驾驶域控制器（ADCU），具备 L2.9 级自动驾驶功能。请使用中文回答问题，请直接返回纯JSON，不要使用 Markdown 代码块，不要有任何说明文字，直接输出 JSON 对象。"
        logger.debug(f"System prompt set: {self._system_prompt[:50]}...")

    def assistant_builder(self) -> DeepSeekAIAssistant:
        """
        Build AI assistant instance

        Returns:
            DeepSeekAIAssistant: The built AI assistant instance
        """
        logger.debug("Starting to build AI assistant instance")
        try:
            # 从配置文件中读取API密钥和其他配置
            assistant = DeepSeekAIAssistant(
                api_key=cfg.DEEPSEEK_API_KEY,
                model=cfg.DEEPSEEK_MODEL,
                base_url=cfg.DEEPSEEK_BASE_URL,
                max_retries=cfg.DEEPSEEK_MAX_RETRIES,
                timeout=cfg.DEEPSEEK_TIMEOUT,
            )
            logger.info("AI assistant instance built successfully")
            return assistant
        except Exception as e:
            logger.error(f"Failed to build AI assistant instance: {str(e)}")
            raise

    def analyze_asset(
        self, msg: str, prompt: str, format_text: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Analyze asset security attributes
        Args:
            msg: User message
            prompt: Prompt text
            **kwargs: Other parameters
        Returns:
            Dict[str, Any]: Analysis results
        Raises:
            ValueError: When parameters are invalid
            RuntimeError: When analysis fails
        """

        try:
            # Parameter validation
            logger.debug("Starting to validate analysis parameters")
            if not msg or not prompt:
                error_msg = "Message and prompt cannot be empty"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Set default parameters
            default_params = {
                "temperature": 0.3,  # Reduce randomness, increase consistency
                "max_tokens": cfg.DEEPSEEK_MAX_TOKENS,
            }
            # Merge default parameters with user-provided parameters
            request_params = {**default_params, **kwargs}
            logger.debug(
                f"Analysis request parameters set: temperature={request_params['temperature']}, max_tokens={request_params['max_tokens']}"
            )

            # Call AI assistant for analysis
            logger.info(
                f"Starting asset security attribute analysis, first 100 chars of asset info: {msg[:100]}..."
            )
            response = self.ai_assistant.request_ai_response(
                system_msg=self._system_prompt,
                msg=msg,
                prompt=prompt,
                format_text=format_text,
                **request_params,
            )
            if not response:
                logger.warning("AI analysis returned empty result")
            else:
                logger.info(
                    "Asset security attribute analysis completed successfully, results obtained"
                )
                logger.debug(f"Analysis results: {response}")

            return response

        except ValueError as e:
            # Parameter error, log detailed error information
            error_msg = f"Parameter validation failed: {str(e)}"
            logger.error(error_msg)
            raise
        except Exception as e:
            # Log detailed error information
            error_msg = f"Failed to analyze asset security attributes: {str(e)}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    async def analyze_asset_async(
        self, msg: str, prompt: str, format_text: str, **kwargs
    ):
        """
        Async version of analyze_asset
        Analyze asset security attributes asynchronously
        Args:
            msg: User message
            prompt: Prompt text
            format_text: Format text for AI response
            **kwargs: Other parameters
        Returns:
            Dict[str, Any]: Analysis results
        Raises:
            ValueError: When parameters are invalid
            RuntimeError: When analysis fails
        """

        try:
            # Parameter validation
            logger.debug("Starting to validate analysis parameters (async)")
            if not msg or not prompt:
                error_msg = "Message and prompt cannot be empty"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Set default parameters
            default_params = {
                "temperature": 0.3,  # Reduce randomness, increase consistency
                "max_tokens": cfg.DEEPSEEK_MAX_TOKENS,
            }
            # Merge default parameters with user-provided parameters
            request_params = {**default_params, **kwargs}
            logger.debug(
                f"Async analysis request parameters set: temperature={request_params['temperature']}, max_tokens={request_params['max_tokens']}"
            )

            # Call AI assistant for analysis asynchronously
            logger.info(
                f"Starting async asset security attribute analysis, first 100 chars of asset info: {msg[:100]}..."
            )
            async with self.ai_assistant as assistant:
                response = await assistant.request_ai_response_async(
                    system_msg=self._system_prompt,
                    msg=msg,
                    prompt=prompt,
                    format_text=format_text,
                    **request_params,
                )
            if not response:
                logger.warning("Async AI analysis returned empty result")
            else:
                logger.info(
                    "Async asset security attribute analysis completed successfully, results obtained"
                )
                logger.debug(f"Async analysis results: {response}")

            return response

        except ValueError as e:
            # Parameter error, log detailed error information
            error_msg = f"Parameter validation failed (async): {str(e)}"
            logger.error(error_msg)
            raise
        except Exception as e:
            # Log detailed error information
            error_msg = (
                f"Failed to analyze asset security attributes asynchronously: {str(e)}"
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
