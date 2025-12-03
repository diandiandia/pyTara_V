from typing import Dict, Any
from ai_assistant.base_ai import BaseAIAssistant
import requests
import aiohttp
import asyncio
from config.logging_config import setup_logger
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time

# Configure logging
logger = setup_logger()


class DeepSeekAIAssistant(BaseAIAssistant):
    """
    DeepSeek model implementation
    """

    def __init__(
        self,
        api_key: str,
        model: str = "Pro/deepseek-ai/DeepSeek-V3.2-Exp",
        base_url: str = "https://api.siliconflow.cn",
        max_retries: int = 3,
        timeout: int = 60,  # Increased from 30 to 60 seconds
    ):
        """
        Initialize DeepSeek model

        Args:
            api_key (str): DeepSeek API key
            model (str): Model name, default "Pro/deepseek-ai/DeepSeek-V3.2-Exp"
            base_url (str): API base URL, default "https://api.siliconflow.cn"
            max_retries (int): Maximum retry attempts, default 3
            timeout (int): Request timeout in seconds, default 60
        """
        logger.info(f"Initializing DeepSeekAIAssistant with model: {model}")
        super().__init__(api_key, base_url, max_retries, timeout)
        self.model = model
        self.session = self._create_session()  # Create session with connection pooling
        # 异步会话将在需要时创建
        self.async_session = None
        logger.debug(
            f"DeepSeekAIAssistant initialized successfully with timeout: {timeout}s and max retries: {max_retries}"
        )

    def _create_session(self):
        """
        Create a requests session with connection pooling and retry strategy
        """
        session = requests.Session()

        # Configure retry strategy with backoff
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=0.3,  # Exponential backoff: 0.3, 0.6, 1.2 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST", "GET"],
        )

        # Create adapter with retry strategy
        adapter = HTTPAdapter(
            max_retries=retry_strategy, pool_connections=10, pool_maxsize=10
        )

        # Mount adapter to both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        logger.debug("Created session with connection pooling and retry strategy")
        return session

    async def _create_async_session(self):
        """
        Create an aiohttp session with connection pooling
        """
        if self.async_session is None or self.async_session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.async_session = aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(
                    limit=10,  # 限制并发连接数
                    limit_per_host=10,  # 限制每个主机的连接数
                    ttl_dns_cache=300,  # DNS缓存时间
                ),
            )
            logger.debug("Created async session with connection pooling")
        return self.async_session

    async def _close_async_session(self):
        """
        Close the async session
        """
        if self.async_session and not self.async_session.closed:
            await self.async_session.close()
            logger.debug("Closed async session")

    def _prepare_request_data(
        self, system_msg: str, msg: str, prompt: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Prepare DeepSeek API request data

        Args:
            system_msg (str): System prompt
            msg (str): User message
            prompt (str): Prompt text
            **kwargs: Other parameters like temperature, max_tokens, etc.

        Returns:
            Dict[str, Any]: Request data dictionary
        """
        logger.debug("Preparing request data for DeepSeek API call")

        # Build message list
        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": msg},
            {"role": "user", "content": prompt},
        ]

        # Prepare request parameters
        request_data = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 5000),
            "stream": kwargs.get("stream", False),
        }

        # Add other optional parameters
        for param in ["top_p", "frequency_penalty", "presence_penalty", "stop"]:
            if param in kwargs:
                request_data[param] = kwargs[param]
                logger.debug(f"Added optional parameter: {param} = {kwargs[param]}")

        logger.debug(
            f"Request data prepared with temperature: {request_data['temperature']}, max_tokens: {request_data['max_tokens']}"
        )
        return request_data

    # 新增异步方法：准备请求数据
    async def _prepare_request_data_async(
        self, system_msg: str, msg: str, prompt: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Asynchronously prepare DeepSeek API request data

        Args:
            system_msg (str): System prompt
            msg (str): User message
            prompt (str): Prompt text
            **kwargs: Other parameters like temperature, max_tokens, etc.

        Returns:
            Dict[str, Any]: Request data dictionary
        """
        # 对于请求数据准备，异步版本可以直接调用同步版本
        return self._prepare_request_data(system_msg, msg, prompt, **kwargs)

    def _send_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to DeepSeek API

        Args:
            request_data (Dict[str, Any]): Request data

        Returns:
            Dict[str, Any]: API response data

        Raises:
            requests.RequestException: When request fails
        """
        # Build complete URL
        url = f"{self.base_url}/v1/chat/completions"
        logger.info(f"Sending request to DeepSeek API: {url}")

        # Prepare request headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # Store original timeout for potential dynamic adjustment
        current_timeout = self.timeout

        for attempt in range(self.max_retries + 1):  # +1 for initial attempt
            try:
                # Send request using session with connection pooling
                logger.debug(
                    f"Request headers prepared, sending POST request (Attempt {attempt + 1}/{self.max_retries + 1})"
                )
                start_time = time.time()
                response = self.session.post(
                    url, headers=headers, json=request_data, timeout=current_timeout
                )
                elapsed_time = time.time() - start_time
                logger.debug(f"Request completed in {elapsed_time:.2f} seconds")

                # Check response status
                response.raise_for_status()
                logger.info(
                    f"API request successful with status code: {response.status_code}"
                )

                # Return JSON response
                json_response = response.json()
                logger.debug(f"Received response from DeepSeek API: {json_response}")
                return json_response
            except requests.exceptions.Timeout as e:
                error_msg = f"Request timed out after {current_timeout} seconds (Attempt {attempt + 1}/{self.max_retries + 1})"
                logger.warning(error_msg)

                # Increase timeout for next attempt
                current_timeout = min(
                    current_timeout * 1.5, 120
                )  # Increase by 50%, max 120s
                logger.debug(
                    f"Increasing timeout to {current_timeout} seconds for next attempt"
                )

                # If this was the last attempt, raise the error
                if attempt == self.max_retries:
                    logger.error(f"All timeout retry attempts failed: {str(e)}")
                    raise

                # Wait before retrying (exponential backoff)
                wait_time = 2**attempt
                logger.debug(f"Waiting {wait_time} seconds before retry")
                time.sleep(wait_time)
            except requests.exceptions.HTTPError as e:
                error_msg = f"HTTP error occurred: {e}"
                logger.error(
                    f"{error_msg}, Status Code: {response.status_code if 'response' in locals() else 'N/A'}"
                )
                # If this was the last attempt or critical error, raise
                if attempt == self.max_retries or (
                    hasattr(response, "status_code") and response.status_code >= 500
                ):
                    raise
                # Wait before retrying
                time.sleep(2**attempt)
            except requests.exceptions.RequestException as e:
                error_msg = f"Request failed: {e}"
                logger.error(error_msg)
                # If this was the last attempt, raise
                if attempt == self.max_retries:
                    raise
                # Wait before retrying
                time.sleep(2**attempt)

    # 新增异步方法：发送请求
    async def _send_request_async(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Asynchronously send request to DeepSeek API

        Args:
            request_data (Dict[str, Any]): Request data

        Returns:
            Dict[str, Any]: API response data

        Raises:
            aiohttp.ClientError: When request fails
        """
        # Build complete URL
        url = f"{self.base_url}/v1/chat/completions"
        logger.info(f"Sending async request to DeepSeek API: {url}")

        # Prepare request headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # Store original timeout for potential dynamic adjustment
        current_timeout = self.timeout

        for attempt in range(self.max_retries + 1):  # +1 for initial attempt
            try:
                # 获取或创建异步会话
                session = await self._create_async_session()

                # Send request using async session
                logger.debug(
                    f"Request headers prepared, sending async POST request (Attempt {attempt + 1}/{self.max_retries + 1})"
                )
                start_time = time.time()
                async with session.post(
                    url, headers=headers, json=request_data, timeout=current_timeout
                ) as response:
                    elapsed_time = time.time() - start_time
                    logger.debug(
                        f"Async request completed in {elapsed_time:.2f} seconds"
                    )

                    # Check response status
                    response.raise_for_status()
                    logger.info(
                        f"Async API request successful with status code: {response.status}"
                    )

                    # Return JSON response
                    json_response = await response.json()
                    logger.debug(
                        f"Received response from DeepSeek API: {json_response}"
                    )
                    return json_response
            except asyncio.TimeoutError as e:
                error_msg = f"Async request timed out after {current_timeout} seconds (Attempt {attempt + 1}/{self.max_retries + 1})"
                logger.warning(error_msg)

                # Increase timeout for next attempt
                current_timeout = min(
                    current_timeout * 1.5, 120
                )  # Increase by 50%, max 120s
                logger.debug(
                    f"Increasing timeout to {current_timeout} seconds for next attempt"
                )

                # If this was the last attempt, raise the error
                if attempt == self.max_retries:
                    logger.error(f"All async timeout retry attempts failed: {str(e)}")
                    raise

                # Wait before retrying (exponential backoff)
                wait_time = 2**attempt
                logger.debug(f"Waiting {wait_time} seconds before async retry")
                await asyncio.sleep(wait_time)
            except aiohttp.ClientResponseError as e:
                error_msg = f"Async HTTP error occurred: {e}"
                logger.error(f"{error_msg}, Status Code: {e.status}")
                # If this was the last attempt or critical error, raise
                if attempt == self.max_retries or e.status >= 500:
                    raise
                # Wait before retrying
                await asyncio.sleep(2**attempt)
            except aiohttp.ClientError as e:
                error_msg = f"Async request failed: {e}"
                logger.error(error_msg)
                # If this was the last attempt, raise
                if attempt == self.max_retries:
                    raise
                # Wait before retrying
                await asyncio.sleep(2**attempt)

    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse DeepSeek API response

        Args:
            response (Dict[str, Any]): API response data

        Returns:
            Dict[str, Any]: Parsed response data
        """
        logger.debug("Parsing DeepSeek API response")

        # Extract content from response
        if response.get("choices") and len(response["choices"]) > 0:
            content = response["choices"][0]["message"]["content"]
            logger.debug(f"Extracted content from response: {content[:100]}...")
            content = content.strip().replace("\n", "").replace(";", ",")

            try:
                # Try to parse content as JSON
                result = self._validate_json_response(content)
                logger.debug("Successfully parsed response as JSON")
                return result
            except ValueError:
                # If not JSON, return original content
                logger.warning(
                    "Response content is not valid JSON, returning as plain text"
                )
                return {"content": content}
        else:
            logger.warning("No valid choices found in the API response")

        return response

    # 添加异步上下文管理器支持
    async def __aenter__(self):
        await self._create_async_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close_async_session()
