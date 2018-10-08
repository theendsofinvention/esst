# coding=utf-8
"""
Clean folders of old files
"""
# import datetime
# import os


from esst import LOGGER


# FIXME
# def parse_age_string(age_str):
#     """
#     Converts age string to datetime timestamp
#
#     Args:
#         age_str: human friendly age string
#
#     Returns: datetime timestamp
#
#     """
#     time_struct, parse_status = parsedatetime.Calendar().parse(age_str)
#     if parse_status != 1:
#         LOGGER.error(f'unable to parse age: {age_str}')
#         return False
#     return datetime.datetime(*time_struct[:6]).timestamp()


# def remove_file_if_older_than(file_path, age):
#     """
#     Removes file if it's older than age
#
#     Args:
#         file_path: path to file to remove
#         age: maximum age of file
#     """
#     file = os.path.abspath(file_path)
#     if not os.path.exists(file):
#         LOGGER.error(f'file does not exist: {file}')
#         return
#     modification_time = os.path.getmtime(file)
#     # LOGGER.debug(f'"{file}" modification time: {modification_time}')
#     if modification_time <= age:
#         LOGGER.info(f'removing: {file}')
#         os.unlink(file)


# def _remove_old_files_from_folder(folder, age):
#     LOGGER.info(f'cleaning folder "{folder}" of all files older than {age}')
#
#     age = parse_age_string(age)
#     if not age:
#         return
#
#     for root, _, files in os.walk(folder):
#         for file in files:
#             remove_file_if_older_than(os.path.join(root, file), age)


def clean_all_folder():
    """
    Cleans all folders according to current config
    """
    LOGGER.warning('removal of old files has been temporarily disabled')
    # paths_to_clean = CFG.remove_files
    # if paths_to_clean:  # pylint: disable=using-constant-test
    #     for remove_config in paths_to_clean:  # pylint: disable=not-an-iterable
    #         name = tuple(remove_config.keys())[0]
    #         LOGGER.info(f'processing: {name}')
    #         remove_config = remove_config[name]
    #         if 'folder' not in remove_config.keys():
    #             LOGGER.error(f'missing "folder" in {name}')
    #             return
    #         if 'age' not in remove_config.keys():
    #             LOGGER.error(f'missing "age" in {name}')
    #             return
    #         if not os.path.exists(remove_config['folder']):
    #             LOGGER.error(f'path does not exist: {remove_config["folder"]}')
    #             return
    #         _remove_old_files_from_folder(**remove_config)
    # else:
    #     LOGGER.debug('no folder to clean')
