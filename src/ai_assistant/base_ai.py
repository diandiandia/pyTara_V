import json
import time
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from config.logging_config import setup_logger

# Configure logging
logger = setup_logger()


class BaseAIAssistant(ABC):
    """
    AI model calling base class, providing common retry mechanism and error handling
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        max_retries: int = 3,
        timeout: int = 30,
        rate_limit_per_minute: int = 20,  # 请求频率限制，默认每分钟60次
        max_burst: int = 10,  # 最大突发请求数
    ):
        """
        Initialize AI model base class
        Args:
            api_key (str): API key
            base_url (Optional[str]): API base URL, required for some models
            max_retries (int): Maximum number of retries, default 3 times
            timeout (int): Request timeout in seconds, default 30 seconds
            rate_limit_per_minute (int): Maximum number of requests per minute, default 60
            max_burst (int): Maximum number of burst requests, default 10
        """
        self.api_key = api_key
        self.base_url = base_url
        self.max_retries = max_retries
        self.timeout = timeout

        # 频率限制相关参数
        self.rate_limit_per_minute = rate_limit_per_minute
        self.max_burst = max_burst
        self.tokens = max_burst  # 当前可用令牌数
        self.last_refill_time = time.time()
        self.token_refill_rate = rate_limit_per_minute / 60.0  # 每秒补充的令牌数

        # 异步锁，用于在异步环境中保护令牌桶操作
        self._async_lock = asyncio.Lock()

    def _refill_tokens(self):
        """
        补充令牌到令牌桶
        """
        current_time = time.time()
        elapsed = current_time - self.last_refill_time

        # 计算应该补充的令牌数
        new_tokens = elapsed * self.token_refill_rate
        if new_tokens > 0:
            self.tokens = min(self.max_burst, self.tokens + new_tokens)
            self.last_refill_time = current_time

    async def _refill_tokens_async(self):
        """
        异步版本：补充令牌到令牌桶
        """
        current_time = time.time()
        elapsed = current_time - self.last_refill_time

        # 计算应该补充的令牌数
        new_tokens = elapsed * self.token_refill_rate
        if new_tokens > 0:
            self.tokens = min(self.max_burst, self.tokens + new_tokens)
            self.last_refill_time = current_time

    def _acquire_token(self, required_tokens: int = 1):
        """
        获取令牌，如果没有足够的令牌则等待

        Args:
            required_tokens (int): 需要的令牌数量，默认为1
        """
        while True:
            self._refill_tokens()

            if self.tokens >= required_tokens:
                self.tokens -= required_tokens
                return True

            # 计算需要等待的时间来获取足够的令牌
            wait_time = (required_tokens - self.tokens) / self.token_refill_rate
            logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds")
            time.sleep(wait_time)

    async def _acquire_token_async(self, required_tokens: int = 1):
        """
        异步版本：获取令牌，如果没有足够的令牌则等待

        Args:
            required_tokens (int): 需要的令牌数量，默认为1
        """
        while True:
            async with self._async_lock:
                await self._refill_tokens_async()

                if self.tokens >= required_tokens:
                    self.tokens -= required_tokens
                    return True

                # 计算需要等待的时间来获取足够的令牌
                wait_time = (required_tokens - self.tokens) / self.token_refill_rate
                logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds")

            await asyncio.sleep(wait_time)

    @abstractmethod
    def _prepare_request_data(
        self, system_msg: str, msg: str, prompt: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Prepare request data, to be implemented by subclasses

        Args:
            **kwargs: Other parameters

        Returns:
            Dict[str, Any]: Request data dictionary
        """
        pass

    @abstractmethod
    def _send_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to AI model API, to be implemented by subclasses

        Args:
            request_data (Dict[str, Any]): Request data

        Returns:
            Dict[str, Any]: API response data
        """
        pass

    # 新增异步抽象方法
    @abstractmethod
    async def _prepare_request_data_async(
        self, system_msg: str, msg: str, prompt: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Asynchronously prepare request data, to be implemented by subclasses

        Args:
            **kwargs: Other parameters

        Returns:
            Dict[str, Any]: Request data dictionary
        """
        pass

    @abstractmethod
    async def _send_request_async(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Asynchronously send request to AI model API, to be implemented by subclasses

        Args:
            request_data (Dict[str, Any]): Request data

        Returns:
            Dict[str, Any]: API response data
        """
        pass

    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse API response and extract useful information
        Subclasses can override this method to adapt to different API response formats

        Args:
            response (Dict[str, Any]): API response data

        Returns:
            Dict[str, Any]: Parsed response data
        """
        return response

    async def _parse_response_async(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Asynchronously parse API response and extract useful information

        Args:
            response (Dict[str, Any]): API response data

        Returns:
            Dict[str, Any]: Parsed response data
        """
        # 默认实现可以直接调用同步版本
        return self._parse_response(response)

    def request_ai_response(
        self, system_msg: str, msg: str, prompt: str, format_text: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generate AI response, including retry mechanism

        Args:
            **kwargs: Other parameters

        Returns:
            Dict[str, Any]: Parsed response data

        Raises:
            Exception: If all retries fail
        """
        retry_count = 0
        last_error = None

        while retry_count <= self.max_retries:
            try:
                # 频率限制：获取令牌
                self._acquire_token()

                # Prepare request data
                request_data = self._prepare_request_data(
                    system_msg, msg, prompt, **kwargs
                )

                # Send request
                logger.info(
                    f"Sending request to AI model, attempt {retry_count + 1}/{self.max_retries + 1}"
                )
                response = self._send_request(request_data)

                # Parse response
                parsed_response = self._parse_response(response)

                # Validate if response is valid JSON format
                if isinstance(parsed_response, dict):
                    logger.info("Successfully obtained and parsed AI model response")
                    if self._validate_response_format(parsed_response, format_text):
                        return parsed_response
                    else:
                        raise ValueError(
                            "AI model returned response format does not match expectations"
                        )
                else:
                    raise ValueError(
                        "AI model returned response is not a valid dictionary format"
                    )

            except Exception as e:
                last_error = e
                retry_count += 1
                logger.warning(f"Request failed: {str(e)}")

                if retry_count <= self.max_retries:
                    # Calculate retry delay (exponential backoff)
                    delay = min(2 ** (retry_count - 1), 30)  # Maximum delay 30 seconds
                    logger.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    logger.error("All retries failed")

        # Throw exception after all retries fail
        raise Exception(
            f"AI model call failed, retried {self.max_retries} times: {str(last_error)}"
        )

    # 新增异步请求方法
    async def request_ai_response_async(
        self, system_msg: str, msg: str, prompt: str, format_text: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Asynchronously generate AI response, including retry mechanism

        Args:
            **kwargs: Other parameters

        Returns:
            Dict[str, Any]: Parsed response data

        Raises:
            Exception: If all retries fail
        """
        retry_count = 0
        last_error = None

        while retry_count <= self.max_retries:
            try:
                # 频率限制：异步获取令牌
                await self._acquire_token_async()

                # Prepare request data asynchronously
                request_data = await self._prepare_request_data_async(
                    system_msg, msg, prompt, **kwargs
                )

                # Send request asynchronously
                logger.info(
                    f"Sending async request to AI model, attempt {retry_count + 1}/{self.max_retries + 1}"
                )
                response = await self._send_request_async(request_data)

                # Parse response asynchronously
                parsed_response = await self._parse_response_async(response)

                # Validate if response is valid JSON format
                if isinstance(parsed_response, dict):
                    logger.info(
                        "Successfully obtained and parsed AI model response asynchronously"
                    )
                    if self._validate_response_format(parsed_response, format_text):
                        return parsed_response
                    else:
                        raise ValueError(
                            "AI model returned response format does not match expectations"
                        )
                else:
                    raise ValueError(
                        "AI model returned response is not a valid dictionary format"
                    )

            except Exception as e:
                last_error = e
                retry_count += 1
                logger.warning(f"Async request failed: {str(e)}")

                if retry_count <= self.max_retries:
                    # Calculate retry delay (exponential backoff)
                    delay = min(2 ** (retry_count - 1), 30)  # Maximum delay 30 seconds
                    logger.info(f"Retrying async request in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    logger.error("All async retries failed")

        # Throw exception after all retries fail
        raise Exception(
            f"Async AI model call failed, retried {self.max_retries} times: {str(last_error)}"
        )

    def _validate_json_response(self, response_text: str) -> Dict[str, Any]:
        """
        Validate and parse JSON response

        Args:
            response_text (str): Response text

        Returns:
            Dict[str, Any]: Parsed JSON data

        Raises:
            ValueError: If response is not valid JSON
        """
        try:
            # Try to parse JSON directly
            return json.loads(response_text)
        except json.JSONDecodeError:
            # If direct parsing fails, try to extract JSON part
            try:
                # Find the start and end positions of JSON
                start = response_text.find("{")
                end = response_text.rfind("}") + 1
                if start != -1 and end != 0:
                    json_str = response_text[start:end]
                    return json.loads(json_str)
            except Exception:
                pass

            # If still failing, throw exception
            raise ValueError(
                f"Failed to parse valid JSON from response: {response_text}"
            )

    def _validate_response_format(
        self, response_json: Dict[str, Any], format_text: str
    ) -> bool:
        """
        Validate if the returned response_json matches the format according to the input format_text JSON string
        Supports handling dynamic number of items (such as damage_scenario_1, damage_scenario_2, etc.)

        Args:
            response_json (Dict[str, Any]): Response JSON data
            format_text (str): Expected format text (can be sample format, not strict JSON Schema)
            Possible inputs include:
            {"possible_damage_scenario_list":[{"damage_scenario_1":"XXXXXXXXX"},{"damage_scenario_2":"XXXXXXXXXXX"}]}
            {"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}
            {"Authenticity":4, "Integrity":3, "Non-repudiation":1, "Confidentiality":1, "Availability":1, "Authorization":1, "Privacy":5 }
            {"possible_threat_scenario_list":[{"threat_scenario_1":"threat_scenario_discription_1"},{"threat_scenario_2":"threat_scenario_discription_2"}]}
            {"possible_attack_path_list":[{"attack_path1":"attack_path1_description"},{"attack_path2":"attack_path2_description"}]}
            {"time_consuming":"no_more_than_1d", "expertise":"layman", "knowledge_about_toe":"public", "window_of_opportunity":"unlimited", "equipment":"standard"}
            {"risk_treatment":"avoid","item_change":"通过移除危险源，停止相关安全开发活动来避免风险发生", "cybersecurity_goal":"", "cybersecurity_claim":""}
            {"cybersecurity_control_id":"CSO-001", "cybersecurity_control":"通过移除危险源，停止相关安全开发活动来避免风险发生", "allocated_to_device":"yes", "cybersecurity_requirement_id":"CSR-001", "cybersecurity_requirement":"确保资产的安全开发活动得到适当的支持和监控"}
            {"asset_cybersecurity_requirement_list":[{"asset_id":"资产ID","asset_name":"资产名称","cybersecurity_requirement_id":"网络安全要求ID","csr_id":"CSR ID","title":"要求标题","sub_title":"要求副标题","cybersecurity_requirement":"网络安全要求内容"},{"asset_id":"资产ID","asset_name":"资产名称","cybersecurity_requirement_id":"网络安全要求ID","csr_id":"CSR ID","title":"要求标题","sub_title":"要求副标题","cybersecurity_requirement":"网络安全要求内容"}]}

            bool: Return True if response matches format, otherwise False
        """
        try:
            # Try to parse format_text as JSON
            format_json = json.loads(format_text)

            # Validate top-level keys
            for key, format_value in format_json.items():
                if key in [
                    "possible_damage_scenario_list",
                    "possible_threat_scenario_list",
                    "possible_attack_path_list",
                    "asset_cybersecurity_requirement_list",
                ]:
                    if key not in response_json:
                        logger.warning(f"00-Response missing required key: {key} in {response_json}")
                        return False
                    if len(response_json[key]) == 0:
                        return False
                    else:
                        for item in response_json[key]:
                            for sub_key, sub_content in item.items():
                                if sub_content.strip() == "":
                                    logger.warning(
                                        f"Response missing required key: {key}->{sub_key}"
                                    )
                                    return False
                elif isinstance(format_value, dict):
                    for sub_key, sub_format_value in format_value.items():
                        if sub_key not in response_json[key]:
                            logger.warning(
                                f"Response missing required key: {key}->{sub_key}"
                            )
                            return False
                else:
                    if key not in response_json:
                        logger.warning(f"11-Response missing required key: {key} in {response_json}")
                        return False

            logger.debug("Response format validation passed")
            return True

        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Response format validation failed: {str(e)}")
            return False
