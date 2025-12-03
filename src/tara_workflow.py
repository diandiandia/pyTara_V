from config.logging_config import setup_logger
from tara_objs.asset_info import AssetInfo
from tara_objs.asset_info_cybersecurity_attribute import AssetInfoCybersecurityAttribute
from ai_assistant.tara_analyzer import TARAAnalyzer
from tara_objs.asset_info_attribute_damage_impact import DamageScenarioImpactLevel
from tara_objs.threat_scenario_attack_feasibility import ThreatScenarioAttackFeasibility
from tara_objs.risk_treatment_decision import RiskTreatmentDecision
from tara_objs.cybersecurity_control_requirement import CybersecurityControlRequirement
from tara_objs.asset_tara_info import AssetTaraInfo
from tara_objs.asset_csr_info import AssetCSRInfo
from typing import List

import copy
import asyncio

logger = setup_logger()


def exec_tara_analysis_workflow(asset_file: str, output_file: str, outout_csr_file: str):
    # 加载资产信息
    logger.info(f"Loading asset information from {asset_file}...")
    try:
        asset_objects = AssetInfo.read_assets_from_excel(asset_file)
        logger.info(f"Loaded {len(asset_objects)} assets successfully.")
    except Exception as e:
        logger.error(f"Failed to load asset information: {e}")
        return

    asset_tara_info_list = []
    asset_csr_info_list = []
    for i, asset_object in enumerate(asset_objects):
        logger.info(
            f"Processing asset {i + 1}/{len(asset_objects)}: {asset_object.asset_name}"
        )
        temp_file = f"tmp/temp_asset_tara_info_{asset_object.asset_id}.csv"
        csr_temp_file = f"tmp/temp_asset_csr_info_{asset_object.asset_id}.csv"
        single_asset_tara_info_list, single_asset_csr_list = tara_analyzer_single_asset(
            asset_object,
            save_to_temp_file=True,
            temp_file=temp_file,
            csr_temp_file=csr_temp_file,
        )

        asset_tara_info_list.extend(single_asset_tara_info_list)
        asset_csr_info_list.extend(single_asset_csr_list)

        logger.info(
            f"Asset {asset_object.asset_name} TARA analysis completed. Generated {len(single_asset_tara_info_list)} entries."
        )
        logger.info(
            f"Asset {asset_object.asset_name} CSR analysis completed. Generated {len(single_asset_csr_list)} entries."
        )
    # 保存资产安全信息到csv
    logger.info(f"Saving TARA analysis results to {output_file}, {outout_csr_file} ...")
    AssetTaraInfo.write_asset_tara_info_to_csv(asset_tara_info_list, output_file)
    AssetCSRInfo.write_asset_csr_info_to_csv(asset_csr_info_list, outout_csr_file)
    logger.info(f"TARA analysis results saved successfully to {output_file}, {outout_csr_file}")


# 修复 exec_tara_analysis_workflow_async 函数
async def exec_tara_analysis_workflow_async(
    asset_file: str,
    output_file: str,
    outout_csr_file: str,
    max_concurrent_assets=5,
    max_concurrent_attributes=10,
):
    # 加载资产信息
    logger.info(f"Loading asset information from {asset_file}...")
    try:
        asset_objects = AssetInfo.read_assets_from_excel(asset_file)
        logger.info(f"Loaded {len(asset_objects)} assets successfully.")
    except Exception as e:
        logger.error(f"Failed to load asset information: {e}")
        return  # 只在出错时返回

    # 创建信号量控制并发
    asset_semaphore = asyncio.Semaphore(max_concurrent_assets)  # 控制最大资产并发数
    attribute_semaphore = asyncio.Semaphore(
        max_concurrent_attributes
    )  # 控制最大属性并发数
    tasks = []
    for asset_object in asset_objects:
        temp_file = f"tmp/temp_asset_tara_info_{asset_object.asset_id}.csv"
        csr_temp_file = f"tmp/temp_asset_csr_info_{asset_object.asset_id}.csv"
        task = tara_analyzer_single_asset_async(
            asset_object,
            save_to_temp_file=True,
            temp_file=temp_file,
            csr_temp_file=csr_temp_file,
            asset_semaphore=asset_semaphore,
            attribute_semaphore=attribute_semaphore,
        )
        tasks.append(task)

    # 并发处理所有资产
    logger.info(f"Starting concurrent processing of {len(tasks)} assets...")
    results = await asyncio.gather(*tasks, return_exceptions=True)

    asset_tara_info_list = []
    asset_csr_info_list = []

    for i, result in enumerate(results):
        asset = asset_objects[i]
        if isinstance(result, Exception):
            logger.error(f"Error processing asset {asset.asset_name}: {result}")
            continue

        single_asset_tara_info_list, single_asset_csr_list = result
        asset_tara_info_list.extend(single_asset_tara_info_list)
        asset_csr_info_list.extend(single_asset_csr_list)

        logger.info(
            f"Asset {asset.asset_name} TARA analysis completed. Generated {len(single_asset_tara_info_list)} entries."
        )
        logger.info(
            f"Asset {asset.asset_name} CSR analysis completed. Generated {len(single_asset_csr_list)} entries."
        )

    # 保存资产安全信息到csv
    logger.info(f"Saving TARA analysis results to {output_file}, {outout_csr_file} ...")
    AssetTaraInfo.write_asset_tara_info_to_csv(asset_tara_info_list, output_file)
    AssetCSRInfo.write_asset_csr_info_to_csv(asset_csr_info_list, outout_csr_file)
    logger.info(
        f"TARA analysis results saved successfully to {output_file}, {outout_csr_file}"
    )


def tara_analyzer_single_asset(
    asset: AssetInfo, save_to_temp_file: bool, temp_file: str, csr_temp_file: str
):
    """
    分析单个资产的安全属性

    Args:
        asset (AssetInfo): 资产信息对象
    """
    logger.info(f"Starting single asset analysis for: {asset.asset_name}")
    asset_cybersecurity_info_list = []
    # 先获取资产的安全属性信息
    asset_info_cybersecurity_attribute_list = (
        get_possible_asset_cybersecurity_attribute_objects(asset)
    )
    logger.info(
        f"Found {len(asset_info_cybersecurity_attribute_list)} cybersecurity attributes for asset {asset.asset_name}"
    )

    for asset_info_cybersecurity_attribute in asset_info_cybersecurity_attribute_list:
        attribute_name = (
            asset_info_cybersecurity_attribute.asset_cybersecurity_attribute.assigned_security_attribute
        )
        logger.debug(f"Processing attribute: {attribute_name}")
        # 对每个资产与相关的信息安全属性，进行损害场景影响评估
        asset_damage_scenario_impact_level_list = asset_damage_scenario_assessment(
            asset_info_cybersecurity_attribute
        )
        logger.info(
            f"Generated {len(asset_damage_scenario_impact_level_list)} damage scenarios for attribute {attribute_name}"
        )

        # 对每一个damage scenario进行威胁评估
        for (
            asset_damage_scenario_impact_level
        ) in asset_damage_scenario_impact_level_list:
            damage_scenario = (
                asset_damage_scenario_impact_level.damage_scenario_impact_level.damage_scenario
            )
            logger.debug(
                f"Analyzing threat scenarios for damage scenario: {damage_scenario}"
            )

            asset_threat_scenario_list = asset_threat_scenario_assessment(
                asset_damage_scenario_impact_level
            )
            logger.info(
                f"Generated {len(asset_threat_scenario_list)} threat scenarios for damage scenario"
            )

            # 对每一个资产进行damage scenario与threat scenario的组合评分，然后给出treatment：avoid reduce share retain
            for asset_threat_scenario in asset_threat_scenario_list:
                threat_scenario = (
                    asset_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
                )
                logger.debug(
                    f"Performing risk treatment assessment for threat: {threat_scenario}"
                )

                asset_threat_risk_treatment_decision = (
                    asset_threat_risk_treatment_assessment(asset_threat_scenario)
                )
                logger.debug(
                    f"Risk treatment decision completed: {asset_threat_risk_treatment_decision.risk_treatment_decision.risk_treatment}"
                )

                logger.debug("Performing CSO/CSR assessment...")
                asset_cso_csr_decision = asset_cso_csr_assessment(
                    asset_threat_risk_treatment_decision
                )
                asset_cybersecurity_info_list.append(asset_cso_csr_decision)
                logger.debug(
                    f"CSO/CSR assessment completed, control ID: {asset_cso_csr_decision.cybersecurity_control_requirement.cybersecurity_control_id}"
                )
    # 对cybersecurity_requirement进行总结，现有的cybersecurity_requirement有哪些，通过总结，原子化拆解，生成对单一资产的信息安全需求。
    single_asset_csr_list = (
        summarize_single_asset_cybersecurity_requirements(asset_cybersecurity_info_list)
    )
    if save_to_temp_file:
        AssetCSRInfo.write_asset_csr_info_to_csv(
            single_asset_csr_list, csr_temp_file
        )
        logger.info(
            f"Generated shrinked cybersecurity requirements for asset {asset.asset_name}, {len(single_asset_csr_list)} entries, save to file: {csr_temp_file}"
        )

    if save_to_temp_file:
        logger.info(f"Saving temporary analysis results to {temp_file}")
        AssetTaraInfo.write_asset_tara_info_to_csv(
            asset_cybersecurity_info_list, temp_file
        )

    logger.info(
        f"Single asset analysis completed for {asset.asset_name}. Generated {len(asset_cybersecurity_info_list)} entries."
    )
    return asset_cybersecurity_info_list, single_asset_csr_list


# 修复 tara_analyzer_single_asset_async 函数
async def tara_analyzer_single_asset_async(
    asset: AssetInfo,
    save_to_temp_file: bool,
    temp_file: str,
    csr_temp_file: str,
    asset_semaphore: asyncio.Semaphore = None,
    attribute_semaphore: asyncio.Semaphore = None,
):
    # 使用资产级信号量控制并发
    if asset_semaphore:
        async with asset_semaphore:
            return await _process_asset_async(
                asset, save_to_temp_file, temp_file, csr_temp_file, attribute_semaphore
            )
    else:
        return await _process_asset_async(
            asset, save_to_temp_file, temp_file, csr_temp_file, attribute_semaphore
        )


async def _process_asset_async(
    asset, save_to_temp_file, temp_file, csr_temp_file, attribute_semaphore
):
    """提取的资产处理逻辑"""
    asset_cybersecurity_info_list = []
    # 先获取资产的安全属性信息
    asset_info_cybersecurity_attribute_list = (
        await get_possible_asset_cybersecurity_attribute_objects_async(asset)
    )
    logger.info(
        f"[async] Found {len(asset_info_cybersecurity_attribute_list)} cybersecurity attributes for asset {asset.asset_name}"
    )

    # 创建任务列表，并发处理所有安全属性
    attribute_tasks = []
    # 在创建属性任务时传入属性级信号量
    for asset_info_cybersecurity_attribute in asset_info_cybersecurity_attribute_list:
        attribute_tasks.append(
            process_attribute_async(
                asset_info_cybersecurity_attribute,
                attribute_semaphore=attribute_semaphore,
            )
        )

    # 并发处理所有安全属性
    attribute_results = await asyncio.gather(*attribute_tasks, return_exceptions=True)

    for i, result in enumerate(attribute_results):
        asset_info_cybersecurity_attribute = asset_info_cybersecurity_attribute_list[i]
        attribute_name = (
            asset_info_cybersecurity_attribute.asset_cybersecurity_attribute.assigned_security_attribute
        )

        if isinstance(result, Exception):
            logger.error(
                f"[async] Error processing attribute {attribute_name}: {result}"
            )
            continue

        # 收集所有结果
        asset_cybersecurity_info_list.extend(result)

    # 对cybersecurity_requirement进行总结，现有的cybersecurity_requirement有哪些，通过总结，原子化拆解，生成对单一资产的信息安全需求。
    single_asset_csr_list = summarize_single_asset_cybersecurity_requirements(
        asset_cybersecurity_info_list
    )
    if save_to_temp_file:
        AssetCSRInfo.write_asset_csr_info_to_csv(single_asset_csr_list, csr_temp_file)
        logger.info(
            f"[async] Generated shrinked cybersecurity requirements for asset {asset.asset_name}, {len(single_asset_csr_list)} entries, save to file: {csr_temp_file}"
        )

    if save_to_temp_file:
        logger.info(f"[async] Saving temporary analysis results to {temp_file}")
        AssetTaraInfo.write_asset_tara_info_to_csv(
            asset_cybersecurity_info_list, temp_file
        )

    logger.info(
        f"[async] Single asset analysis completed for {asset.asset_name}. Generated {len(asset_cybersecurity_info_list)} entries."
    )
    return asset_cybersecurity_info_list, single_asset_csr_list


async def process_attribute_async(
    asset_info_cybersecurity_attribute, attribute_semaphore=None
):
    """异步处理单个安全属性

    Args:
        asset_info_cybersecurity_attribute: 资产安全属性对象
        attribute_semaphore (asyncio.Semaphore, optional): 用于控制属性处理并发的信号量
    """
    attribute_name = (
        asset_info_cybersecurity_attribute.asset_cybersecurity_attribute.assigned_security_attribute
    )
    logger.debug(f"[async] Processing attribute: {attribute_name}")

    # 使用属性级信号量控制并发处理
    if attribute_semaphore:
        async with attribute_semaphore:
            # 对每个资产与相关的信息安全属性，进行损害场景影响评估
            asset_damage_scenario_impact_level_list = (
                await asset_damage_scenario_assessment_async(
                    asset_info_cybersecurity_attribute
                )
            )
            logger.info(
                f"[async] Generated {len(asset_damage_scenario_impact_level_list)} damage scenarios for attribute {attribute_name}"
            )

            results = []
            # 并发处理所有损害场景
            damage_scenario_tasks = []
            for (
                asset_damage_scenario_impact_level
            ) in asset_damage_scenario_impact_level_list:
                damage_scenario_tasks.append(
                    process_damage_scenario_async(asset_damage_scenario_impact_level)
                )

            damage_scenario_results = await asyncio.gather(
                *damage_scenario_tasks, return_exceptions=True
            )

            for i, result in enumerate(damage_scenario_results):
                asset_damage_scenario_impact_level = (
                    asset_damage_scenario_impact_level_list[i]
                )
                damage_scenario = (
                    asset_damage_scenario_impact_level.damage_scenario_impact_level.damage_scenario
                )

                if isinstance(result, Exception):
                    logger.error(
                        f"[async] Error processing damage scenario '{damage_scenario}': {result}"
                    )
                    continue

                results.extend(result)

            return results
    else:
        # 没有信号量时的处理逻辑（保持原有行为）
        asset_damage_scenario_impact_level_list = (
            await asset_damage_scenario_assessment_async(
                asset_info_cybersecurity_attribute
            )
        )
        logger.info(
            f"[async] Generated {len(asset_damage_scenario_impact_level_list)} damage scenarios for attribute {attribute_name}"
        )

        results = []
        # 并发处理所有损害场景
        damage_scenario_tasks = []
        for (
            asset_damage_scenario_impact_level
        ) in asset_damage_scenario_impact_level_list:
            damage_scenario_tasks.append(
                process_damage_scenario_async(asset_damage_scenario_impact_level)
            )

        damage_scenario_results = await asyncio.gather(
            *damage_scenario_tasks, return_exceptions=True
        )

        for i, result in enumerate(damage_scenario_results):
            asset_damage_scenario_impact_level = (
                asset_damage_scenario_impact_level_list[i]
            )
            damage_scenario = (
                asset_damage_scenario_impact_level.damage_scenario_impact_level.damage_scenario
            )

            if isinstance(result, Exception):
                logger.error(
                    f"[async] Error processing damage scenario '{damage_scenario}': {result}"
                )
                continue

            results.extend(result)

        return results


async def process_damage_scenario_async(asset_damage_scenario_impact_level):
    """异步处理单个损害场景"""
    damage_scenario = (
        asset_damage_scenario_impact_level.damage_scenario_impact_level.damage_scenario
    )
    logger.debug(
        f"[async] Analyzing threat scenarios for damage scenario: {damage_scenario}"
    )

    # 对每一个damage scenario进行威胁评估
    asset_threat_scenario_list = await asset_threat_scenario_assessment_async(
        asset_damage_scenario_impact_level
    )
    logger.info(
        f"[async] Generated {len(asset_threat_scenario_list)} threat scenarios for damage scenario"
    )

    results = []
    # 并发处理所有威胁场景
    threat_scenario_tasks = []
    for asset_threat_scenario in asset_threat_scenario_list:
        threat_scenario_tasks.append(
            process_threat_scenario_async(asset_threat_scenario)
        )

    threat_scenario_results = await asyncio.gather(
        *threat_scenario_tasks, return_exceptions=True
    )

    for i, result in enumerate(threat_scenario_results):
        asset_threat_scenario = asset_threat_scenario_list[i]
        threat_scenario = (
            asset_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
        )

        if isinstance(result, Exception):
            logger.error(
                f"[async] Error processing threat scenario '{threat_scenario}': {result}"
            )
            continue

        if result:
            results.append(result)

    return results


async def process_threat_scenario_async(asset_threat_scenario):
    """异步处理单个威胁场景，增加更健壮的错误处理"""
    threat_scenario = (
        asset_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
    )
    logger.debug(
        f"[async] Performing risk treatment assessment for threat: {threat_scenario}"
    )

    retry_count = 0
    max_retries = 2

    while retry_count <= max_retries:
        try:
            asset_threat_risk_treatment_decision = (
                await asset_threat_risk_treatment_assessment_async(
                    asset_threat_scenario
                )
            )
            logger.debug(
                f"[async] Risk treatment decision completed: {asset_threat_risk_treatment_decision.risk_treatment_decision.risk_treatment}"
            )

            logger.debug("[async] Performing CSO/CSR assessment...")
            asset_cso_csr_decision = await asset_cso_csr_assessment_async(
                asset_threat_risk_treatment_decision
            )
            logger.debug(
                f"[async] CSO/CSR assessment completed, control ID: {asset_cso_csr_decision.cybersecurity_control_requirement.cybersecurity_control_id}"
            )
            return asset_cso_csr_decision
        except Exception as e:
            retry_count += 1
            if retry_count > max_retries:
                logger.error(
                    f"[async] Error in threat scenario processing after {max_retries} retries: {e}"
                )
                return None
            logger.warning(
                f"[async] Retry {retry_count}/{max_retries} for threat scenario '{threat_scenario}': {e}"
            )
            # 指数退避
            await asyncio.sleep(2 ** (retry_count - 1))


def get_possible_damage_scenario_impact_level_list(
    asset_info_cybersecurity_attribute: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    """
    获取资产信息安全属性可能的损害场景信息

    Args:
        asset_info_cybersecurity_attribute (AssetTaraInfo): 资产信息安全属性对象

    Returns:
        list[AssetTaraInfo]: 让AI生成可能的damage scenrios的AssetTaraInfo列表

    """
    logger.debug("Generating possible damage scenarios using AI analysis...")
    msg = asset_info_cybersecurity_attribute.prepare_for_ai01()
    prompt = asset_info_cybersecurity_attribute.get_prompt02()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_damage_scenario_list":[{"damage_scenario_1":"资产被未授权用户访问"},{"damage_scenario_2":"资产数据被篡改"}]}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"AI analysis for damage scenarios completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"Failed to get damage scenarios from AI analysis: {e}")
        raise

    # {"possible_damage_scenario_list":[{"damage_scenario_1":"资产被未授权用户访问"},{"damage_scenario_2":"资产数据被篡改"}]}
    damage_scenario_impact_level_list = []
    for item in analysis_result["possible_damage_scenario_list"]:
        for key, value in item.items():
            damage_scenario_impact_level = DamageScenarioImpactLevel(
                damage_scenario_sn=key,
                damage_scenario=value,
            )
            asset_info_cybersecurity_attribute_new = copy.deepcopy(
                asset_info_cybersecurity_attribute
            )
            asset_info_cybersecurity_attribute_new.damage_scenario_impact_level = (
                damage_scenario_impact_level
            )
            damage_scenario_impact_level_list.append(
                asset_info_cybersecurity_attribute_new
            )

    logger.debug(
        f"Generated {len(damage_scenario_impact_level_list)} damage scenario objects"
    )
    return damage_scenario_impact_level_list


async def get_possible_damage_scenario_impact_level_list_async(
    asset_info_cybersecurity_attribute: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    """
    异步获取资产信息安全属性可能的损害场景信息

    Args:
        asset_info_cybersecurity_attribute (AssetTaraInfo): 资产信息安全属性对象

    Returns:
        list[AssetTaraInfo]: 让AI生成可能的damage scenrios的AssetTaraInfo列表

    """
    logger.debug("[async] Generating possible damage scenarios using AI analysis...")
    msg = asset_info_cybersecurity_attribute.prepare_for_ai01()
    prompt = asset_info_cybersecurity_attribute.get_prompt02()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_damage_scenario_list":[{"damage_scenario_1":"资产被未授权用户访问"},{"damage_scenario_2":"资产数据被篡改"}]}'
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI analysis for damage scenarios completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"[async] Failed to get damage scenarios from AI analysis: {e}")
        raise

    # {"possible_damage_scenario_list":[{"damage_scenario_1":"资产被未授权用户访问"},{"damage_scenario_2":"资产数据被篡改"}]}
    damage_scenario_impact_level_list = []
    for item in analysis_result["possible_damage_scenario_list"]:
        for key, value in item.items():
            damage_scenario_impact_level = DamageScenarioImpactLevel(
                damage_scenario_sn=key,
                damage_scenario=value,
            )
            asset_info_cybersecurity_attribute_new = copy.deepcopy(
                asset_info_cybersecurity_attribute
            )
            asset_info_cybersecurity_attribute_new.damage_scenario_impact_level = (
                damage_scenario_impact_level
            )
            damage_scenario_impact_level_list.append(
                asset_info_cybersecurity_attribute_new
            )

    logger.debug(
        f"[async] Generated {len(damage_scenario_impact_level_list)} damage scenario objects"
    )
    return damage_scenario_impact_level_list


def get_possible_damage_scenario_impact_level(
    asset_damage_scenario_impact_level: AssetTaraInfo,
) -> AssetTaraInfo:
    """
    获取资产信息安全属性可能的损害场景影响级别
    Args:
        asset_damage_scenario_impact_level (AssetInfoAttributeDamageImpact): 资产信息安全属性损害场景影响级别对象
    Returns:
        AssetInfoAttributeDamageImpact: 可能的损害场景影响级别对象
    """
    damage_scenario = (
        asset_damage_scenario_impact_level.damage_scenario_impact_level.damage_scenario
    )
    logger.debug(f"Assessing impact level for damage scenario: {damage_scenario}")

    msg = asset_damage_scenario_impact_level.prepare_for_ai02()
    prompt = asset_damage_scenario_impact_level.get_prompt03()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(f"AI impact level analysis completed. Result: {analysis_result}")
    except Exception as e:
        logger.error(f"Failed to get impact level from AI analysis: {e}")
        raise

    # 返回safety，financial，operational，privacy 4个方面的影响级别{"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}
    asset_damage_scenario_impact_level.damage_scenario_impact_level.set_impact_levels_by_strings(
        attributes=analysis_result["possible_damage_scenario_impact_level"]
    )
    logger.debug("Impact levels set successfully for damage scenario")
    return asset_damage_scenario_impact_level


async def get_possible_damage_scenario_impact_level_async(
    asset_damage_scenario_impact_level: AssetTaraInfo,
) -> AssetTaraInfo:
    """
    异步获取资产信息安全属性可能的损害场景影响级别
    Args:
        asset_damage_scenario_impact_level (AssetInfoAttributeDamageImpact): 资产信息安全属性损害场景影响级别对象
    Returns:
        AssetInfoAttributeDamageImpact: 可能的损害场景影响级别对象
    """
    damage_scenario = (
        asset_damage_scenario_impact_level.damage_scenario_impact_level.damage_scenario
    )
    logger.debug(
        f"[async] Assessing impact level for damage scenario: {damage_scenario}"
    )

    msg = asset_damage_scenario_impact_level.prepare_for_ai02()
    prompt = asset_damage_scenario_impact_level.get_prompt03()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}'
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI impact level analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"[async] Failed to get impact level from AI analysis: {e}")
        raise

    # 返回safety，financial，operational，privacy 4个方面的影响级别{"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}
    asset_damage_scenario_impact_level.damage_scenario_impact_level.set_impact_levels_by_strings(
        attributes=analysis_result["possible_damage_scenario_impact_level"]
    )
    logger.debug("[async] Impact levels set successfully for damage scenario")
    return asset_damage_scenario_impact_level


def asset_damage_scenario_assessment(
    asset_info_cybersecurity_attribute: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    logger.info("Starting damage scenario assessment...")
    # 获取可能的damage scenrio信息
    damage_scenario_impact_level_list = get_possible_damage_scenario_impact_level_list(
        asset_info_cybersecurity_attribute
    )

    # 对每个damage scenario，进行损害场景影响评估
    possible_damage_scenario_impact_level_list = []
    for damage_scenario_impact_level in damage_scenario_impact_level_list:
        possible_damage_scenario_impact_level = (
            get_possible_damage_scenario_impact_level(damage_scenario_impact_level)
        )
        possible_damage_scenario_impact_level_list.append(
            possible_damage_scenario_impact_level
        )

    logger.info(
        f"Damage scenario assessment completed. Processed {len(possible_damage_scenario_impact_level_list)} scenarios."
    )
    return possible_damage_scenario_impact_level_list


async def asset_damage_scenario_assessment_async(
    asset_info_cybersecurity_attribute: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    logger.info("[async] Starting damage scenario assessment...")
    # 获取可能的damage scenrio信息
    damage_scenario_impact_level_list = (
        await get_possible_damage_scenario_impact_level_list_async(
            asset_info_cybersecurity_attribute
        )
    )

    # 对每个damage scenario，进行损害场景影响评估
    tasks = []
    for damage_scenario_impact_level in damage_scenario_impact_level_list:
        tasks.append(
            get_possible_damage_scenario_impact_level_async(
                damage_scenario_impact_level
            )
        )

    # 并发处理所有损害场景
    possible_damage_scenario_impact_level_list = await asyncio.gather(
        *tasks, return_exceptions=True
    )

    # 过滤异常结果
    valid_results = []
    for i, result in enumerate(possible_damage_scenario_impact_level_list):
        if isinstance(result, Exception):
            damage_scenario = damage_scenario_impact_level_list[
                i
            ].damage_scenario_impact_level.damage_scenario
            logger.error(
                f"[async] Error processing damage scenario '{damage_scenario}': {result}"
            )
        else:
            valid_results.append(result)

    logger.info(
        f"[async] Damage scenario assessment completed. Processed {len(valid_results)} scenarios."
    )
    return valid_results


def get_possible_asset_cybersecurity_attribute_objects(
    asset_info: AssetInfo,
) -> list[AssetTaraInfo]:
    """
    根据资产类型获取可能的安全属性对象列表
    Args:
        asset_info (AssetInfo): 资产信息对象
    Returns:
        list[AssetTaraInfo]: 可能的安全属性对象列表
    """
    logger.debug(f"Creating AssetTaraInfo object for asset: {asset_info.asset_name}")
    asset_tara_info = AssetTaraInfo(
        asset_cybersecurity_attribute=AssetInfoCybersecurityAttribute(
            asset_info=asset_info
        )
    )

    logger.debug("Analyzing cybersecurity attributes using AI...")
    msg = asset_tara_info.prepare_for_ai01()
    prompt = asset_tara_info.get_prompt01()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"Authenticity":4, "Integrity":3, "Non-repudiation":1, "Confidentiality":1, "Availability":1, "Authorization":1, "Privacy":5 }'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(f"AI attribute analysis completed. Result: {analysis_result}")
    except Exception as e:
        logger.error(f"Failed to get cybersecurity attributes from AI analysis: {e}")
        raise

    asset_info_cybersecurity_attribute_list = []
    # {"Authenticity":4, "Integrity":3, "Non-repudiation":1, "Confidentiality":1, "Availability":1, "Authorization":1, "Privacy":5 }
    for attr, score in analysis_result.items():
        if not isinstance(score, int) or score < 0 or score > 5:
            logger.warning(
                f"Invalid score for attribute {attr}: {score}. Score must be an integer between 0 and 5."
            )
            raise ValueError(
                f"Invalid score for attribute {attr}: {score}. Score must be an integer between 0 and 5."
            )
        if score > 2:
            logger.info(
                f"Attribute {attr} with score {score} is selected for further analysis"
            )
            asset_tara_info_new = copy.deepcopy(asset_tara_info)
            asset_tara_info_new.asset_cybersecurity_attribute.assign_security_attribute(
                attr
            )
            asset_info_cybersecurity_attribute_list.append(asset_tara_info_new)

    logger.info(
        f"Selected {len(asset_info_cybersecurity_attribute_list)} cybersecurity attributes for asset {asset_info.asset_name}"
    )
    return asset_info_cybersecurity_attribute_list


async def get_possible_asset_cybersecurity_attribute_objects_async(
    asset_info: AssetInfo,
) -> list[AssetTaraInfo]:
    """
    异步根据资产类型获取可能的安全属性对象列表
    Args:
        asset_info (AssetInfo): 资产信息对象
    Returns:
        list[AssetTaraInfo]: 可能的安全属性对象列表
    """
    logger.debug(
        f"[async] Creating AssetTaraInfo object for asset: {asset_info.asset_name}"
    )
    asset_tara_info = AssetTaraInfo(
        asset_cybersecurity_attribute=AssetInfoCybersecurityAttribute(
            asset_info=asset_info
        )
    )

    logger.debug("[async] Analyzing cybersecurity attributes using AI...")
    msg = asset_tara_info.prepare_for_ai01()
    prompt = asset_tara_info.get_prompt01()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"Authenticity":4, "Integrity":3, "Non-repudiation":1, "Confidentiality":1, "Availability":1, "Authorization":1, "Privacy":5 }'
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI attribute analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(
            f"[async] Failed to get cybersecurity attributes from AI analysis: {e}"
        )
        raise

    asset_info_cybersecurity_attribute_list = []
    # {"Authenticity":4, "Integrity":3, "Non-repudiation":1, "Confidentiality":1, "Availability":1, "Authorization":1, "Privacy":5 }
    for attr, score in analysis_result.items():
        if not isinstance(score, int) or score < 0 or score > 5:
            logger.warning(
                f"[async] Invalid score for attribute {attr}: {score}. Score must be an integer between 0 and 5."
            )
            raise ValueError(
                f"Invalid score for attribute {attr}: {score}. Score must be an integer between 0 and 5."
            )
        if score > 2:
            logger.debug(
                f"[async] Attribute {attr} with score {score} is selected for further analysis"
            )
            asset_tara_info_new = copy.deepcopy(asset_tara_info)
            asset_tara_info_new.asset_cybersecurity_attribute.assign_security_attribute(
                attr
            )
            asset_info_cybersecurity_attribute_list.append(asset_tara_info_new)

    logger.info(
        f"[async] Selected {len(asset_info_cybersecurity_attribute_list)} cybersecurity attributes for asset {asset_info.asset_name}"
    )
    return asset_info_cybersecurity_attribute_list


def get_possible_threat_scenario_info(
    asset_damage_scenario_impact_level: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    logger.debug("Generating threat scenarios using AI analysis...")
    msg = asset_damage_scenario_impact_level.prepare_for_ai02()
    prompt = asset_damage_scenario_impact_level.get_prompt04()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_threat_scenario_list":[{"threat_scenario_1":"threat_scenario_discription_1"},{"threat_scenario_2":"threat_scenario_discription_2"}]}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"AI threat scenario analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"Failed to get threat scenarios from AI analysis: {e}")
        raise

    # 返回值格式：{"possible_threat_scenario_list":[{"threat_scenario_1":"threat_scenario_discription_1"},{"threat_scenario_2":"threat_scenario_discription_2"}]}
    asset_info_damage_scenario_threat_scenario_list = []
    for item in analysis_result["possible_threat_scenario_list"]:
        for key, value in item.items():
            logger.debug(f"Creating threat scenario {key}: {value}")
            threat_scenario_info = ThreatScenarioAttackFeasibility(
                threat_id=key,
                threat_scenario=value,
                attack_path="",
            )
            asset_damage_scenario_impact_level_new = copy.deepcopy(
                asset_damage_scenario_impact_level
            )

            asset_damage_scenario_impact_level_new.set_threat_scenario(
                threat_scenario_info
            )
            asset_info_damage_scenario_threat_scenario_list.append(
                asset_damage_scenario_impact_level_new
            )

    logger.info(
        f"Generated {len(asset_info_damage_scenario_threat_scenario_list)} threat scenarios"
    )
    return asset_info_damage_scenario_threat_scenario_list


async def get_possible_threat_scenario_info_async(
    asset_damage_scenario_impact_level: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    logger.debug("[async] Generating threat scenarios using AI analysis...")
    msg = asset_damage_scenario_impact_level.prepare_for_ai02()
    prompt = asset_damage_scenario_impact_level.get_prompt04()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_threat_scenario_list":[{"threat_scenario_1":"threat_scenario_discription_1"},{"threat_scenario_2":"threat_scenario_discription_2"}]}'
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI threat scenario analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"[async] Failed to get threat scenarios from AI analysis: {e}")
        raise

    # 返回值格式：{"possible_threat_scenario_list":[{"threat_scenario_1":"threat_scenario_discription_1"},{"threat_scenario_2":"threat_scenario_discription_2"}]}
    asset_info_damage_scenario_threat_scenario_list = []
    for item in analysis_result["possible_threat_scenario_list"]:
        for key, value in item.items():
            logger.debug(f"[async] Creating threat scenario {key}: {value}")
            threat_scenario_info = ThreatScenarioAttackFeasibility(
                threat_id=key,
                threat_scenario=value,
                attack_path="",
            )
            asset_damage_scenario_impact_level_new = copy.deepcopy(
                asset_damage_scenario_impact_level
            )

            asset_damage_scenario_impact_level_new.set_threat_scenario(
                threat_scenario_info
            )
            asset_info_damage_scenario_threat_scenario_list.append(
                asset_damage_scenario_impact_level_new
            )

    logger.info(
        f"[async] Generated {len(asset_info_damage_scenario_threat_scenario_list)} threat scenarios"
    )
    return asset_info_damage_scenario_threat_scenario_list


def get_possible_threat_scenario_attack_path(
    asset_damage_scenario_threat_scenario: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    """
    对于每一个threat scenario，获取所有可能的攻击路径
    Args:
        asset_damage_scenario_threat_scenario (AssetTaraInfo): 资产损害场景威胁场景综合分析对象
    Returns:
        list: 所有可能的攻击路径对象列表
    """
    threat_scenario = (
        asset_damage_scenario_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
    )
    logger.debug(f"Generating attack paths for threat scenario: {threat_scenario}")

    msg = asset_damage_scenario_threat_scenario.prepare_for_ai03()
    prompt = asset_damage_scenario_threat_scenario.get_prompt05()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_attack_path_list":[{"attack_path1":"attack_path1_description"},{"attack_path2":"attack_path2_description"}]}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(f"AI attack path analysis completed. Result: {analysis_result}")
    except Exception as e:
        logger.error(f"Failed to get attack paths from AI analysis: {e}")
        raise

    # {"possible_attack_path_list":[{"attack_path1":"attack_path1_description"},{"attack_path2":"attack_path2_description"}]}
    # 对每个attack path，进行攻击路径可行性评估
    possible_threat_scenario_attack_path_list = []
    for item in analysis_result["possible_attack_path_list"]:
        for key, value in item.items():
            logger.debug(f"Creating attack path {key}: {value}")
            # 深度拷贝一个对象，为对象attach_path赋值
            threat_scenario_attack_path = copy.deepcopy(
                asset_damage_scenario_threat_scenario
            )
            threat_scenario_attack_path.threat_scenario_attack_feasibility.attack_path = (
                value
            )
            possible_threat_scenario_attack_path_list.append(
                threat_scenario_attack_path
            )

    logger.info(
        f"Generated {len(possible_threat_scenario_attack_path_list)} attack paths"
    )
    return possible_threat_scenario_attack_path_list


async def get_possible_threat_scenario_attack_path_async(
    asset_damage_scenario_threat_scenario: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    """
    异步对于每一个threat scenario，获取所有可能的攻击路径
    Args:
        asset_damage_scenario_threat_scenario (AssetTaraInfo): 资产损害场景威胁场景综合分析对象
    Returns:
        list: 所有可能的攻击路径对象列表
    """
    threat_scenario = (
        asset_damage_scenario_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
    )
    logger.debug(
        f"[async] Generating attack paths for threat scenario: {threat_scenario}"
    )

    msg = asset_damage_scenario_threat_scenario.prepare_for_ai03()
    prompt = asset_damage_scenario_threat_scenario.get_prompt05()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"possible_attack_path_list":[{"attack_path1":"attack_path1_description"},{"attack_path2":"attack_path2_description"}]}'
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI attack path analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"[async] Failed to get attack paths from AI analysis: {e}")
        raise

    # {"possible_attack_path_list":[{"attack_path1":"attack_path1_description"},{"attack_path2":"attack_path2_description"}]}
    # 对每个attack path，进行攻击路径可行性评估
    possible_threat_scenario_attack_path_list = []
    for item in analysis_result["possible_attack_path_list"]:
        for key, value in item.items():
            logger.debug(f"[async] Creating attack path {key}: {value}")
            # 深度拷贝一个对象，为对象attach_path赋值
            threat_scenario_attack_path = copy.deepcopy(
                asset_damage_scenario_threat_scenario
            )
            threat_scenario_attack_path.threat_scenario_attack_feasibility.attack_path = (
                value
            )
            possible_threat_scenario_attack_path_list.append(
                threat_scenario_attack_path
            )

    logger.info(
        f"[async] Generated {len(possible_threat_scenario_attack_path_list)} attack paths"
    )
    return possible_threat_scenario_attack_path_list


def get_possible_threat_scenario_attack_path_feasibilities(
    threat_scenario_attack_path: AssetTaraInfo,
) -> AssetTaraInfo:
    attack_path = (
        threat_scenario_attack_path.threat_scenario_attack_feasibility.attack_path
    )
    logger.debug(f"Assessing attack path feasibility: {attack_path}")

    msg = threat_scenario_attack_path.prepare_for_ai03()
    prompt = threat_scenario_attack_path.get_prompt06()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"time_consuming":"no_more_than_1d", "expertise":"layman", "knowledge_about_toe":"public", "window_of_opportunity":"unlimited", "equipment":"standard"}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"AI attack feasibility analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"Failed to get attack feasibility from AI analysis: {e}")
        raise

    # {"time_consuming":"no_more_than_1d", "expertise":"layman", "knowledge_about_toe":"public", "window_of_opportunity":"unlimited", "equipment":"standard"}
    # 对每个attack path，进行攻击路径可行性评估
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_time_consuming(
        analysis_result["time_consuming"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_expertise(
        analysis_result["expertise"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_knowledge_about_toe(
        analysis_result["knowledge_about_toe"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_window_of_opportunity(
        analysis_result["window_of_opportunity"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_equipment(
        analysis_result["equipment"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.update_feasibility_rating()

    logger.debug(
        f"Attack feasibility assessment completed. Rating: {threat_scenario_attack_path.threat_scenario_attack_feasibility.attack_feasibility_rating}"
    )
    return threat_scenario_attack_path


async def get_possible_threat_scenario_attack_path_feasibilities_async(
    threat_scenario_attack_path: AssetTaraInfo,
) -> AssetTaraInfo:
    attack_path = (
        threat_scenario_attack_path.threat_scenario_attack_feasibility.attack_path
    )
    logger.debug(f"[async] Assessing attack path feasibility: {attack_path}")

    msg = threat_scenario_attack_path.prepare_for_ai03()
    prompt = threat_scenario_attack_path.get_prompt06()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"time_consuming":"no_more_than_1d", "expertise":"layman", "knowledge_about_toe":"public", "window_of_opportunity":"unlimited", "equipment":"standard"}'
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI attack feasibility analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(f"[async] Failed to get attack feasibility from AI analysis: {e}")
        raise

    # {"time_consuming":"no_more_than_1d", "expertise":"layman", "knowledge_about_toe":"public", "window_of_opportunity":"unlimited", "equipment":"standard"}
    # 对每个attack path，进行攻击路径可行性评估
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_time_consuming(
        analysis_result["time_consuming"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_expertise(
        analysis_result["expertise"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_knowledge_about_toe(
        analysis_result["knowledge_about_toe"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_window_of_opportunity(
        analysis_result["window_of_opportunity"]
    )
    threat_scenario_attack_path.threat_scenario_attack_feasibility.set_equipment(
        analysis_result["equipment"]
    )

    threat_scenario_attack_path.threat_scenario_attack_feasibility.update_feasibility_rating()

    logger.debug(
        f"Attack feasibility assessment completed. Rating: {threat_scenario_attack_path.threat_scenario_attack_feasibility.attack_feasibility_rating}"
    )
    return threat_scenario_attack_path


def asset_threat_scenario_assessment(
    asset_damage_scenario_impact_level: AssetTaraInfo,
) -> list:
    """
    获取资产信息安全属性可能的威胁场景
    Args:
        asset_damage_scenario_impact_level (AssetInfoAttributeDamageImpact): 资产信息安全属性损害场景影响级别对象
    Returns:
    """
    logger.info("Starting threat scenario assessment...")
    # 获取可能的threat scenario信息
    possible_threat_scenario_attack_path_feasibilities_list = []
    possible_asset_damage_scenario_threat_scenario_list = (
        get_possible_threat_scenario_info(asset_damage_scenario_impact_level)
    )

    # 对每个threat scenario，进行威胁场景影响评估
    for i, (asset_damage_scenario_threat_scenario) in enumerate(
        possible_asset_damage_scenario_threat_scenario_list
    ):
        logger.debug(
            f"Processing threat scenario {i + 1}/{len(possible_asset_damage_scenario_threat_scenario_list)}"
        )
        possible_thread_scenario_attack_path_list = (
            get_possible_threat_scenario_attack_path(
                asset_damage_scenario_threat_scenario
            )
        )

        for threat_scenario_attack_path in possible_thread_scenario_attack_path_list:
            possible_threat_scenario_attack_path_feasibilities = (
                get_possible_threat_scenario_attack_path_feasibilities(
                    threat_scenario_attack_path
                )
            )
            possible_threat_scenario_attack_path_feasibilities_list.append(
                possible_threat_scenario_attack_path_feasibilities
            )

    logger.info(
        f"Threat scenario assessment completed. Generated {len(possible_threat_scenario_attack_path_feasibilities_list)} threat scenario attack paths."
    )
    return possible_threat_scenario_attack_path_feasibilities_list


async def asset_threat_scenario_assessment_async(
    asset_damage_scenario_impact_level: AssetTaraInfo,
) -> list[AssetTaraInfo]:
    logger.info("[async] Starting threat scenario assessment...")
    # 获取可能的threat scenario信息
    asset_threat_scenario_list = await get_possible_threat_scenario_info_async(
        asset_damage_scenario_impact_level
    )

    # 对每个threat scenario，进行攻击路径分析
    possible_threat_scenario_attack_path_list = []

    # 创建任务列表，并发处理所有威胁场景
    threat_scenario_tasks = []
    for asset_threat_scenario in asset_threat_scenario_list:
        threat_scenario_tasks.append(
            process_threat_scenario_with_attack_paths_async(asset_threat_scenario)
        )

    # 并发处理所有威胁场景
    threat_scenario_results = await asyncio.gather(
        *threat_scenario_tasks, return_exceptions=True
    )

    # 收集所有结果
    for i, result in enumerate(threat_scenario_results):
        if isinstance(result, Exception):
            asset_threat_scenario = asset_threat_scenario_list[i]
            threat_scenario = (
                asset_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
            )
            logger.error(
                f"[async] Error processing threat scenario '{threat_scenario}': {result}"
            )
        else:
            possible_threat_scenario_attack_path_list.extend(result)

    logger.info(
        f"[async] Threat scenario assessment completed. Processed {len(possible_threat_scenario_attack_path_list)} attack paths."
    )
    return possible_threat_scenario_attack_path_list


async def process_threat_scenario_with_attack_paths_async(asset_threat_scenario):
    """异步处理单个威胁场景及其攻击路径"""
    results = []
    try:
        # 获取可能的攻击路径
        attack_paths = await get_possible_threat_scenario_attack_path_async(
            asset_threat_scenario
        )

        # 并发处理所有攻击路径
        attack_path_tasks = []
        for attack_path in attack_paths:
            attack_path_tasks.append(
                get_possible_threat_scenario_attack_path_feasibilities_async(
                    attack_path
                )
            )

        attack_path_results = await asyncio.gather(
            *attack_path_tasks, return_exceptions=True
        )

        for i, result in enumerate(attack_path_results):
            if isinstance(result, Exception):
                attack_path = attack_paths[
                    i
                ].threat_scenario_attack_feasibility.attack_path
                logger.error(
                    f"[async] Error processing attack path '{attack_path}': {result}"
                )
            else:
                results.append(result)
    except Exception as e:
        threat_scenario = (
            asset_threat_scenario.threat_scenario_attack_feasibility.threat_scenario
        )
        logger.error(
            f"[async] Error in attack path processing for threat '{threat_scenario}': {e}"
        )

    return results


def asset_threat_risk_treatment_assessment(
    asset_threat_scenario: AssetTaraInfo,
) -> AssetTaraInfo:
    """
    评估资产威胁风险处理决策
    Args:
        asset_threat_scenario (AssetInfoDamageScenarioThreatScenario): 资产威胁场景对象
    Returns:
        AssetTaraInfo: 资产威胁风险处理决策对象
    """
    logger.debug("Creating risk treatment decision object...")
    risk_treatment_decision = RiskTreatmentDecision()

    asset_threat_scenario.set_risk_treatment_decision(risk_treatment_decision)
    asset_threat_scenario.calculate_overall_risk()
    logger.debug(
        f"Overall risk calculated: {asset_threat_scenario.risk_treatment_decision.risk_value}"
    )

    # 评估资产威胁风险处理决策是avoid/share/reduce/retain
    logger.debug("Performing risk treatment decision analysis using AI...")
    msg = asset_threat_scenario.prepare_for_ai04()
    prompt = asset_threat_scenario.get_prompt07()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = '{"risk_treatment":"avoid","item_change":"通过移除危险源，停止相关安全开发活动来避免风险发生", "cybersecurity_goal":"","cybersecurity_claim":""}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(f"AI risk treatment analysis completed. Result: {analysis_result}")
    except Exception as e:
        logger.error(f"Failed to get risk treatment decision from AI analysis: {e}")
        raise

    asset_threat_scenario.risk_treatment_decision.set_risk_treatment(
        risk_treatment=analysis_result["risk_treatment"]
    )
    logger.info(f"Risk treatment decision set to: {analysis_result['risk_treatment']}")

    asset_threat_scenario.risk_treatment_decision.item_change = analysis_result[
        "item_change"
    ]
    asset_threat_scenario.risk_treatment_decision.cybersecurity_goal = analysis_result[
        "cybersecurity_goal"
    ]
    asset_threat_scenario.risk_treatment_decision.cybersecurity_claim = analysis_result[
        "cybersecurity_claim"
    ]

    return asset_threat_scenario


async def asset_threat_risk_treatment_assessment_async(
    asset_threat_scenario: AssetTaraInfo,
) -> AssetTaraInfo:
    logger.debug("Creating risk treatment decision object...")
    risk_treatment_decision = RiskTreatmentDecision()

    asset_threat_scenario.set_risk_treatment_decision(risk_treatment_decision)
    asset_threat_scenario.calculate_overall_risk()
    logger.debug(
        f"Overall risk calculated: {asset_threat_scenario.risk_treatment_decision.risk_value}"
    )

    # 评估资产威胁风险处理决策是avoid/share/reduce/retain
    logger.debug("Performing risk treatment decision analysis using AI...")
    # 准备AI分析所需的消息和提示
    msg = asset_threat_scenario.prepare_for_ai04()
    prompt = asset_threat_scenario.get_prompt07()
    tara_analyzer = TARAAnalyzer()

    try:
        format_text = (
            '{"risk_treatment":"Avoid","item_change":"通过移除危险源，停止相关安全开发活动来避免风险发生", "cybersecurity_goal":"","cybersecurity_claim":""}'  # avoid, reduce, share, retain
        )
        analysis_result = await tara_analyzer.analyze_asset_async(
            msg=msg, prompt=prompt, format_text=format_text
        )
        logger.debug(
            f"[async] AI risk treatment analysis completed. Result: {analysis_result}"
        )
    except Exception as e:
        logger.error(
            f"[async] Failed to get risk treatment decision from AI analysis: {e}"
        )
        raise

    asset_threat_scenario.risk_treatment_decision.set_risk_treatment(
        risk_treatment=analysis_result["risk_treatment"]
    )
    logger.info(f"Risk treatment decision set to: {analysis_result['risk_treatment']}")

    asset_threat_scenario.risk_treatment_decision.item_change = analysis_result[
        "item_change"
    ]
    asset_threat_scenario.risk_treatment_decision.cybersecurity_goal = analysis_result[
        "cybersecurity_goal"
    ]
    asset_threat_scenario.risk_treatment_decision.cybersecurity_claim = analysis_result[
        "cybersecurity_claim"
    ]

    return asset_threat_scenario


def asset_cso_csr_assessment(
    asset_threat_risk_treatment_decision: AssetTaraInfo,
) -> AssetTaraInfo:
    """
    评估资产CSO/CSR决策
    Args:
        asset_threat_risk_treatment_decision (AssetThreatRiskTreatmentDecision): 资产威胁风险处理决策对象
    Returns:
        AssetThreatRiskTreatmentDecision: 资产威胁风险处理决策对象
    """
    logger.debug("Creating cybersecurity control requirement object...")
    asset_threat_risk_treatment_decision.set_cybersecurity_control_requirement(
        cybersecurity_control_requirement=CybersecurityControlRequirement()
    )

    logger.debug("Performing CSO/CSR analysis using AI...")
    # 仅当风险处理决策为reduce时，才进行CSO/CSR评估
    if asset_threat_risk_treatment_decision.risk_treatment_decision.risk_treatment.name.lower() == "reduce":
        msg = asset_threat_risk_treatment_decision.prepare_for_ai05()
        prompt = asset_threat_risk_treatment_decision.get_prompt08()
        tara_analyzer = TARAAnalyzer()

        try:
            format_text = '{"cybersecurity_control_id":"CSO-001", "cybersecurity_control":"通过移除危险源，停止相关安全开发活动来避免风险发生", "allocated_to_device":"yes", "cybersecurity_requirement_id":"CSR-001", "cybersecurity_requirement":"确保资产的安全开发活动得到适当的支持和监控"}'
            analysis_result = tara_analyzer.analyze_asset(
                msg=msg, prompt=prompt, format_text=format_text
            )
            logger.debug(f"AI CSO/CSR analysis completed. Result: {analysis_result}")
        except Exception as e:
            logger.error(f"Failed to get CSO/CSR from AI analysis: {e}")
            raise

        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_control = analysis_result[
            "cybersecurity_control"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.allocated_to_device = analysis_result[
            "allocated_to_device"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_requirement_id = analysis_result[
            "cybersecurity_requirement_id"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_requirement = analysis_result[
            "cybersecurity_requirement"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.regenerate_csr_id()

        logger.info(
            f"CSO/CSR assessment completed. Requirement ID: {asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_requirement_id}"
        )
        return asset_threat_risk_treatment_decision
    else:
        logger.info("Risk treatment decision is not 'reduce', skip CSO/CSR assessment.")
        return asset_threat_risk_treatment_decision


async def asset_cso_csr_assessment_async(
    asset_threat_risk_treatment_decision: AssetTaraInfo,
) -> AssetTaraInfo:
    # 只有当风险处理决策为reduce时，才需要进行CSO/CSR评估
    logger.debug("Creating cybersecurity control requirement object...")
    asset_threat_risk_treatment_decision.set_cybersecurity_control_requirement(
        cybersecurity_control_requirement=CybersecurityControlRequirement()
    )

    logger.debug("Performing CSO/CSR analysis using AI...")
    # 仅当风险处理决策为reduce时，才进行CSO/CSR评估
    if asset_threat_risk_treatment_decision.risk_treatment_decision.risk_treatment.name.lower() == "reduce":
        msg = asset_threat_risk_treatment_decision.prepare_for_ai05()
        prompt = asset_threat_risk_treatment_decision.get_prompt08()
        tara_analyzer = TARAAnalyzer()

        try:
            format_text = '{"cybersecurity_control_id":"CSO-001", "cybersecurity_control":"通过移除危险源，停止相关安全开发活动来避免风险发生", "allocated_to_device":"yes", "cybersecurity_requirement_id":"CSR-001", "cybersecurity_requirement":"确保资产的安全开发活动得到适当的支持和监控"}'

            analysis_result = await tara_analyzer.analyze_asset_async(
                msg=msg, prompt=prompt, format_text=format_text
            )
            logger.debug(
                f"[async] AI CSO/CSR analysis completed. Result: {analysis_result}"
            )
        except Exception as e:
            logger.error(f"[async] Failed to get CSO/CSR from AI analysis: {e}")
            raise

        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_control = analysis_result[
            "cybersecurity_control"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.allocated_to_device = analysis_result[
            "allocated_to_device"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_requirement_id = analysis_result[
            "cybersecurity_requirement_id"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_requirement = analysis_result[
            "cybersecurity_requirement"
        ]
        asset_threat_risk_treatment_decision.cybersecurity_control_requirement.regenerate_csr_id()

        logger.info(
            f"CSO/CSR assessment completed. Requirement ID: {asset_threat_risk_treatment_decision.cybersecurity_control_requirement.cybersecurity_requirement_id}"
        )
        return asset_threat_risk_treatment_decision
    else:
        logger.info("Risk treatment decision is not 'reduce', skip CSO/CSR assessment.")
        return asset_threat_risk_treatment_decision


def summarize_single_asset_cybersecurity_requirements(
    asset_cybersecurity_info_list: List[AssetTaraInfo],
) -> List[AssetCSRInfo]:
    """
    对资产的 cybersecurity_requirement 进行总结，原子化拆解，生成对单一资产的信息安全需求。

    Args:
        asset_cybersecurity_info_list (List[AssetTaraInfo]): 资产的 cybersecurity_requirement 列表

    Returns:
        List[AssetTaraInfo]: 对单一资产的信息安全需求列表
    """
    msg_list = []
    asset_csr_info = None
    for asset_cybersecurity_info in asset_cybersecurity_info_list:
        if asset_cybersecurity_info.cybersecurity_control_requirement.allocated_to_device == "yes":
            msg = asset_cybersecurity_info.prepare_for_ai06()
            msg_list.append(msg)
        if not asset_csr_info:
            asset_csr_info = AssetCSRInfo(
                asset_id=asset_cybersecurity_info.asset_cybersecurity_attribute.asset_info.asset_id,
                asset_name=asset_cybersecurity_info.asset_cybersecurity_attribute.asset_info.asset_name,
            )
    msg_list_str = "\n".join(msg_list)
    prompt = asset_csr_info.get_prompt()
    tara_analyzer = TARAAnalyzer()
    try:
        format_text = '{"asset_cybersecurity_requirement_list":[{"asset_id":"资产ID","asset_name":"资产名称","cybersecurity_requirement_id":"网络安全要求ID","csr_id":"CSR ID","title":"要求标题","sub_title":"要求副标题","cybersecurity_requirement":"网络安全要求内容"},{"asset_id":"资产ID","asset_name":"资产名称","cybersecurity_requirement_id":"网络安全要求ID","csr_id":"CSR ID","title":"要求标题","sub_title":"要求副标题","cybersecurity_requirement":"网络安全要求内容"}]}'
        analysis_result = tara_analyzer.analyze_asset(
            msg=msg_list_str, prompt=prompt, format_text=format_text
        )
        logger.debug(f"AI CSO/CSR analysis completed. Result: {analysis_result}")
    except Exception as e:
        logger.error(f"Failed to get CSO/CSR from AI analysis: {e}")
        raise
    # 根据返回组装AssetCSRInfo
    asset_csr_info_list = []
    if not asset_csr_info:
        asset_csr_info = AssetCSRInfo()
    for item in analysis_result["asset_cybersecurity_requirement_list"]:
        asset_csr_info_new = copy.deepcopy(asset_csr_info)
        asset_csr_info_new.cybersecurity_requirement_id = item[
            "cybersecurity_requirement_id"
        ]
        asset_csr_info_new.csr_id = item["csr_id"]
        asset_csr_info_new.title = item["title"]
        asset_csr_info_new.sub_title = item["sub_title"]
        asset_csr_info_new.cybersecurity_requirement = item["cybersecurity_requirement"]
        asset_csr_info_list.append(asset_csr_info_new)
    return asset_csr_info_list


async def main_async():
    """
    异步主函数
    """
    asset_file = "files/J6P_TARA_1117.xlsx"
    output_file = "files/asset_tara_info.csv"
    csr_output_file = "files/asset_csr_info.csv"

    logger.info("Starting async TARA analysis workflow...")

    try:
        # 减少并发数量，降低服务器压力
        await exec_tara_analysis_workflow_async(
            asset_file=asset_file,
            output_file=output_file,
            outout_csr_file=csr_output_file,
            max_concurrent_assets=2,  # 从5减少到2
            max_concurrent_attributes=3,  # 从10减少到3
        )
        logger.info("Async TARA analysis workflow completed successfully")
    except Exception as e:
        logger.error(f"Async TARA analysis workflow failed: {e}")
        raise


def main():
    logger.info("Starting TARA analysis workflow...")
    try:
        exec_tara_analysis_workflow(
            asset_file="files/J6P_TARA_1117.xlsx",
            output_file="files/tara_analysis_report.csv",
            outout_csr_file="files/csr_report_csr.csv",
        )
        logger.info("TARA analysis workflow completed successfully.")
    except Exception as e:
        logger.error(f"TARA analysis workflow failed: {e}")


if __name__ == "__main__":
    # 同步执行
    # main()

    # 异步执行
    asyncio.run(main_async())
