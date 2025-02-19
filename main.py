import aiohttp
import asyncio
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import quote_plus
from astrbot.api.all import *
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter.event_message_type import EventMessageType
from astrbot.api.provider import LLMResponse
from astrbot.api import logger


@register("astrbot_plugin_aliyun_censor", "Raven95676", "为bot启用阿里云内容安全审核", "1.0.0", "https://github.com/Raven95676/astrbot_plugin_aliyun_censor")
class AliyunCensor(Star):

    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        self.input_active = self.config.get("input_censor")
        self.output_active = self.config.get("output_censor")
        self.endpoint = self.config.get("censor_endpoint")
        self.access_key_id = self.config.get("access_key_id")
        self.access_key_secret = self.config.get("access_key_secret")

    @event_message_type(EventMessageType.ALL, priority=10)
    async def input_censor(self, event: AstrMessageEvent):
        """审核用户输入"""
        if self.input_active:
            if event.is_at_or_wake_command:
                message_str = event.message_str
                if not await self._check_text(str(message_str)):
                    yield event.plain_result("用户输入不合法")

    @filter.on_llm_response()
    async def output_censor(self, event: AstrMessageEvent, response: LLMResponse):
        """审核模型输出"""
        if self.output_active:
            completion_text = response.completion_text
            if not await self._check_text(str(completion_text)):
                response.completion_text = "模型输出不合法"

    def _split_text(self, content: str) -> List[str]:
        """超长文本分割"""
        if not content:
            return []
        chunks = []
        for i in range(0, len(content), 600):
            chunks.append(content[i:i + 600])
        return chunks

    async def _check_single_text(self, content: str) -> bool:
        """单段文本审核"""
        try:
            params_a: Dict[str, str] = {
                "Format": "JSON",
                "Version": "2022-03-02",
                "AccessKeyId": self.access_key_id,
                "SignatureMethod": "HMAC-SHA1",
                "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "SignatureVersion": "1.0",
                "SignatureNonce": str(uuid.uuid4()),
                "Action": "TextModerationPlus",
                "Service": "chat_detection_pro",
                "ServiceParameters": json.dumps({"content": content})
            }

            sorted_params: List = sorted(params_a.items())

            def encode_a(s) -> str:
                return quote_plus(str(s)).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")

            canonicalized_query = "&".join(
                f"{encode_a(k)}={encode_a(v)}" for k, v in sorted_params)
            string_to_sign = f"POST&{encode_a('/')}&{encode_a(canonicalized_query)}"
            key = self.access_key_secret + "&"
            signature = base64.b64encode(
                hmac.new(
                    key.encode("utf-8"),
                    string_to_sign.encode("utf-8"),
                    hashlib.sha1
                ).digest()
            ).decode("utf-8")

            params_a["Signature"] = signature

            async with aiohttp.ClientSession() as session:
                async with session.post(self.endpoint, params=params_a) as response:
                    if response.status != 200:
                        logger.error(f"内容审核HTTP状态错误: {response.status}")
                        return False

                    result = await response.json()
                    if "Data" not in result:
                        logger.error(f"内容审核返回数据异常: {result}")
                        return False

                    risk_level = result["Data"].get("RiskLevel", "").lower()
                    return risk_level != "high"

        except aiohttp.ClientError as e:
            logger.error(f"内容审核网络请求错误: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"内容审核发生未知错误: {str(e)}")
            return False

    async def _check_text(self, content: str) -> bool:
        """所有文本审核"""
        try:
            if not content:
                return True

            if len(content) <= 600:
                return await self._check_single_text(content)

            chunks = self._split_text(content)
            tasks = [self._check_single_text(chunk) for chunk in chunks]
            results = await asyncio.gather(*tasks)
            return all(results)
        except Exception as e:
            return False
