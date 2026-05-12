# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rahul Sandhu <nvraxn@posteo.uk>

# Things to do still:
#   - Consider other kinds of contexts:
#     - customizable_types
#     - dbus_contexts
#     - default_contexts
#     - default_type
#     - failsafe_context
#     - removable_context
#     - maybe more?
#   - Consider SELinux users and how we can install/generate them

from __future__ import annotations
from dataclasses import dataclass
import os
import typing as T

from . import ExtensionModule, ModuleInfo, ModuleReturnValue
from ..interpreter.type_checking import INSTALL_KW, CustomTarget, OptionKey
from ..interpreterbase import typed_pos_args, typed_kwargs, ContainerTypeInfo, KwargInfo
from ..mesonlib import File, FileMode, MesonException

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..interpreter import Interpreter
    from ..programs import CommandList

    class Module(TypedDict):
        sources: T.List[T.Union[str, File]]
        dependencies: T.List[str]
        conflicts: T.List[str]

    class Compile(TypedDict):
        modules: T.List[str]
        policytype: str
        policyvers: int
        mls: bool
        optimize: bool
        neverallow: bool
        extra_args: T.List[str]
        install: bool

@dataclass
class ModuleData:
    sources: T.List[File]
    dependencies: T.List[str]
    conflicts: T.List[str]

def resolve(registry: T.Dict[str, ModuleData], modules: T.List[str]) -> T.Dict[str, ModuleData]:
    ret: T.Dict[str, ModuleData] = {}

    def expand(module: str) -> None:
        if module in ret:
            return
        mod = registry.get(module)
        if not mod:
            raise MesonException(f'module {module} does not exist.')
        ret[module] = mod
        for dep in mod.dependencies:
            expand(dep)

    for module in modules:
        expand(module)

    for name, mod in ret.items():
        for conflict in mod.conflicts:
            if conflict in ret:
                raise MesonException(
                    f'module {name} conflicts with module {conflict}.'
                )

    return ret

class SELinuxModule(ExtensionModule):

    INFO = ModuleInfo('selinux')

    def __init__(self, interpreter: Interpreter) -> None:
        super().__init__(interpreter)

        self.module_registry: T.Dict[str, ModuleData] = {}

        self.methods.update({
            'module': self.module,
            'compile': self.compile,
        })

    @typed_pos_args('selinux.module', str)
    @typed_kwargs(
        'selinux.module',
        KwargInfo(
            'sources',
            ContainerTypeInfo(list, (str, File)),
            default=[],
            listify=True,
        ),
        KwargInfo(
            'dependencies',
            ContainerTypeInfo(list, str),
            default=[],
            listify=True,
        ),
        KwargInfo(
            'conflicts',
            ContainerTypeInfo(list, str),
            default=[],
            listify=True,
        ),
    )
    def module(self, state: ModuleState, args: T.Tuple[str], kwargs: Module):
        name = args[0]

        if name in self.module_registry:
            raise MesonException(
                f'A module by the name of {name} already exists in the registry.'
            )

        sources = [
            File.from_source_file(state.environment.source_dir, state.subdir, s)
            if isinstance(s, str) else s
            for s in kwargs['sources']
        ]

        if not sources:
            raise MesonException(f'module {name} declared without any sources.')

        self.module_registry[name] = ModuleData(
            sources=sources,
            dependencies=kwargs['dependencies'],
            conflicts=kwargs['conflicts'],
        )

    @typed_pos_args('selinux.compile', str)
    @typed_kwargs(
        'selinux.compile',
        KwargInfo(
            'modules',
            ContainerTypeInfo(list, str),
            default=[],
            listify=True,
        ),
        KwargInfo('policytype', str),
        KwargInfo('policyvers', int),
        KwargInfo('mls', bool),
        # TODO: I think meson has some default "generic" way of getting whether
        #       a build is an "optimized" / "release" build or a debug one. We
        #       could possibly use that here?
        KwargInfo('optimize', bool),
        # Disabling this is fucked up... not even sure if I like exposing this.
        KwargInfo('neverallow', bool, default=True),
        KwargInfo(
            'extra_args',
            ContainerTypeInfo(list, str),
            default=[],
            listify=True
        ),
        INSTALL_KW,
    )
    def compile(self, state: ModuleState, args: T.Tuple[str], kwargs: Compile):
        # Preconditions
        if not kwargs['modules']:
            raise MesonException('selinux.compile() called without any modules.')

        # Can't really do much without secilc so should probably find it first.
        secilc = state.find_program('secilc')

        resolved = resolve(self.module_registry, kwargs['modules'])

        # TODO: T.Set[File]?
        sources: T.List[File] = []
        for mod in resolved.values():
            sources.extend(mod.sources)

        # We should always have _some_ sources if we have modules passed to us,
        # as checked above in the preconditions.
        assert sources, 'This is a bug'

        cmd: CommandList = [
            secilc,
            '--mls', 'true' if kwargs['mls'] else 'false',
            f'--policyvers={kwargs['policyvers']}',
        ]
        if kwargs['optimize']:
            cmd.append('--optimize')
        if not kwargs['neverallow']:
            cmd.append('--disable-neverallow')
        cmd += kwargs['extra_args']
        cmd += ['-o', '@OUTPUT0@', '-f', '@OUTPUT1@', '@INPUT@']

        # TODO: This will probably cause some kind of "collision" if we call
        # selinux.compile() in the same directory. This is not something that
        # is inherently _wrong_ for a user to do: for example, you could want
        # to build two separate policy targets, with different names for each
        # target, from the same directory. As such, we may want to "label" the
        # emitted policy and file_contexts with some kind of identifier, e.g.:
        #
        #   policy = f'{args[0]}.{kwargs['policyvers']}'
        #   file_contexts = f'{args[0]}.file_contexts'
        #
        # However, we then have to deal with install shenanigans as the policy
        # must be named in the policy install dir as policy.$policyvers and the
        # file_contexts must be named file_contexts in the contexts directory.
        policy = f'{args[0]}.{kwargs['policyvers']}'
        file_contexts = f'{args[0]}.file_contexts'

        sysconfdir = state.environment.coredata.optstore.get_value_for(
            OptionKey('sysconfdir')
        )

        # Fucking mypy bullshit... not exactly sure why we need this.
        assert isinstance(sysconfdir, str), 'for mypy'

        base_dir = os.path.join(sysconfdir, 'selinux', kwargs['policytype'])
        policy_dir = os.path.join(base_dir, 'policy')
        file_contexts_dir = os.path.join(base_dir, 'contexts', 'files')

        target = CustomTarget(
            args[0],
            state.subdir,
            state.subproject,
            state.environment,
            command=cmd,
            sources=sources,
            outputs=[policy, file_contexts],
            build_by_default=True,
            install=kwargs['install'],
            # TODO: do we the conditional check? I would imagine nothing ever checks
            #       install_dir if install is False...
            install_dir=[policy_dir, file_contexts_dir] if kwargs['install'] else None,
            # TODO: support multiple file modes (have policy.$polvers as 0600).
            install_mode=FileMode('rw-rw----'),
            # TODO: description
        )

        # TODO: could self.interpreter.add_install_script here in theory...

        return ModuleReturnValue(target, [target])

def initialize(interpreter: Interpreter) -> SELinuxModule:
    return SELinuxModule(interpreter)
