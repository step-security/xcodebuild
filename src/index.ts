import {
  actionIsTestable,
  createAppStoreConnectApiKeyFile,
  createKeychain,
  createProvisioningProfiles,
  deleteAppStoreConnectApiKeyFile,
  deleteKeychain,
  deleteProvisioningProfiles,
  getAction,
  getConfiguration,
  getDestination,
  getIdentity,
  getSchemeFromPackage,
  spawn,
  verbosity,
  xcselect,
} from './lib'
import type { Arch, Platform } from './lib'
import xcodebuildX from './xcodebuild'
import { DefaultArtifactClient } from '@actions/artifact'
import * as core from '@actions/core'
import * as fs from 'fs'
import * as path from 'path'
import semver, { Range } from 'semver'
import axios, { isAxiosError } from 'axios'

async function validateSubscription() {
  const eventPath = process.env.GITHUB_EVENT_PATH
  let repoPrivate: boolean | undefined

  if (eventPath && fs.existsSync(eventPath)) {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'))
    repoPrivate = eventData?.repository?.private
  }

  const upstream = 'mxcl/xcodebuild'
  const action = process.env.GITHUB_ACTION_REPOSITORY
  const docsUrl =
    'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions'

  core.info('')
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m')
  core.info(`Secure drop-in replacement for ${upstream}`)
  if (repoPrivate === false)
    core.info('\u001b[32m✓ Free for public repositories\u001b[0m')
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`)
  core.info('')

  if (repoPrivate === false) return

  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com'
  const body: Record<string, string> = { action: action || '' }
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body,
      { timeout: 3000 }
    )
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(
        `\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`
      )
      core.error(
        `\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`
      )
      process.exit(1)
    }
    core.info('Timeout or API not reachable. Continuing to next step.')
  }
}

//TODO we also need to set the right flags for other languages
const warningsAsErrorsFlags = 'OTHER_SWIFT_FLAGS=-warnings-as-errors'

async function main() {
  const cwd = core.getInput('working-directory')
  if (cwd) {
    process.chdir(cwd)
  }

  const swiftPM = fs.existsSync('Package.swift')
  const platform = getPlatformInput('platform')
  const platformVersion = getRangeInput('platform-version')
  const arch = getArchInput('arch')
  const selected = await xcselect(
    getRangeInput('xcode'),
    getRangeInput('swift')
  )
  const action = getAction(selected, platform)
  const configuration = getConfiguration()
  const warningsAsErrors = core.getBooleanInput('warnings-as-errors')
  const destination = await getDestination(selected, platform, platformVersion)
  const identity = getIdentity(core.getInput('code-sign-identity'), platform)
  const currentVerbosity = verbosity()
  const workspace = core.getInput('workspace')

  core.info(`» Selected Xcode ${selected}`)

  const reason: string | false = shouldGenerateXcodeproj()
  if (reason) {
    generateXcodeproj(reason)
  }

  const apiKey = await getAppStoreConnectApiKey()

  await configureKeychain()
  await configureProvisioningProfiles()

  await build(await getScheme(workspace), workspace, arch)

  if (core.getInput('upload-logs') == 'always') {
    await uploadLogs()
  }

  //// immediate funcs

  function getPlatformInput(input: string): Platform | undefined {
    const value = core.getInput(input)
    if (!value) return undefined
    return value as Platform
  }

  function getArchInput(input: string): Arch | undefined {
    const value = core.getInput(input)
    if (!value) return undefined
    return value as Arch
  }

  function getRangeInput(input: string): Range | undefined {
    const value = core.getInput(input)
    if (!value) return undefined
    try {
      return new Range(value)
    } catch (error) {
      throw new Error(
        `failed to parse semantic version range from '${value}': ${error}`
      )
    }
  }

  function shouldGenerateXcodeproj(): string | false {
    if (!swiftPM) return false
    if (platform == 'watchOS' && semver.lt(selected, '12.5.0')) {
      // watchOS prior to 12.4 will fail to `xcodebuild` a SwiftPM project
      // failing trying to build the test modules, so we generate a project
      return 'Xcode <12.5 fails to build Swift Packages for watchOS if tests exist'
    } else if (semver.lt(selected, '11.0.0')) {
      return 'Xcode <11 cannot build'
    } else if (warningsAsErrors) {
      // `build` with SwiftPM projects will build the tests too, and if there are warnings in the
      // tests we will then fail to build (it's common that the tests may have ok warnings)
      //TODO only do this if there are test targets
      return '`warningsAsErrors` is set'
    }
    return false
  }

  function generateXcodeproj(reason: string) {
    core.startGroup('Generating `.xcodeproj`')
    try {
      core.info(`Generating \`.xcodeproj\` ∵ ${reason}`)
      spawn('swift', ['package', 'generate-xcodeproj'])
    } finally {
      core.endGroup()
    }
  }

  async function getAppStoreConnectApiKey(): Promise<string[] | undefined> {
    const key = core.getInput('authentication-key-base64')
    if (!key) return

    if (semver.lt(selected, '13.0.0')) {
      core.notice(
        'Ignoring authentication-key-base64 because it requires Xcode 13 or later.'
      )
      return
    }

    const keyId = core.getInput('authentication-key-id')
    const keyIssuerId = core.getInput('authentication-key-issuer-id')
    if (!keyId || !keyIssuerId) {
      throw new Error(
        'authentication-key-base64 requires authentication-key-id and authentication-key-issuer-id.'
      )
    }

    // The user should have already stored these as encrypted secrets, but we'll
    // be paranoid on their behalf.
    core.setSecret(key)
    core.setSecret(keyId)
    core.setSecret(keyIssuerId)

    const keyPath = await createAppStoreConnectApiKeyFile(key)
    return [
      '-allowProvisioningDeviceRegistration',
      '-allowProvisioningUpdates',
      '-authenticationKeyPath',
      keyPath,
      '-authenticationKeyID',
      keyId,
      '-authenticationKeyIssuerID',
      keyIssuerId,
    ]
  }

  async function configureKeychain() {
    const certificate = core.getInput('code-sign-certificate')
    if (!certificate) return

    if (process.env.RUNNER_OS != 'macOS') {
      throw new Error('code-sign-certificate requires macOS.')
    }

    const passphrase = core.getInput('code-sign-certificate-passphrase')
    if (!passphrase) {
      throw new Error(
        'code-sign-certificate requires code-sign-certificate-passphrase.'
      )
    }

    await core.group('Configuring code signing', async () => {
      await createKeychain(certificate, passphrase)
    })
  }

  async function configureProvisioningProfiles() {
    const mobileProfiles = core.getMultilineInput(
      'mobile-provisioning-profiles-base64'
    )
    const profiles = core.getMultilineInput('provisioning-profiles-base64')
    if (!mobileProfiles.length && !profiles.length) return

    await createProvisioningProfiles(mobileProfiles, profiles)
  }

  async function build(scheme?: string, workspace?: string, arch?: Arch) {
    if (warningsAsErrors && actionIsTestable(action)) {
      await xcodebuild('build', scheme, workspace, arch)
    }
    await xcodebuild(action, scheme, workspace, arch)
  }

  //// helper funcs

  async function xcodebuild(
    action?: string,
    scheme?: string,
    workspace?: string,
    arch?: Arch
  ) {
    if (action === 'none') return

    const title = ['xcodebuild', action].filter((x) => x).join(' ')
    await core.group(title, async () => {
      let args = destination
      if (scheme) args = args.concat(['-scheme', scheme])
      if (arch) args = args.concat([`-arch=${arch}`])
      if (workspace) args = args.concat(['-workspace', workspace])
      if (identity) args = args.concat(identity)
      if (currentVerbosity == 'quiet') args.push('-quiet')
      if (configuration) args = args.concat(['-configuration', configuration])
      if (apiKey) args = args.concat(apiKey)

      args = args.concat([
        '-resultBundlePath',
        `${action ?? 'xcodebuild'}.xcresult`,
      ])

      switch (action) {
        case 'build':
          if (warningsAsErrors) args.push(warningsAsErrorsFlags)
          break
        case 'test':
        case 'build-for-testing': {
          if (core.getBooleanInput('code-coverage')) {
            args = args.concat(['-enableCodeCoverage', 'YES'])
          }
          const sanitizer = core.getInput('sanitizer')
          if (sanitizer === 'thread') {
            args = args.concat(['-enableThreadSanitizer', 'YES'])
          } else if (sanitizer === 'address') {
            args = args.concat(['-enableAddressSanitizer', 'YES'])
          }
          break
        }
      }

      if (core.getBooleanInput('trust-plugins')) {
        core.warning(
          'trust-plugins is enabled: Swift Package Manager build plugin validation is skipped. ' +
            'Malicious build plugins in dependencies could execute arbitrary code. ' +
            'Only enable this if you trust all Swift package dependencies.'
        )
        args.push('-skipPackagePluginValidation')
      }

      if (action) args.push(action)

      await xcodebuildX(args, currentVerbosity)
    })
  }

  //NOTE this is not nearly clever enough I think
  async function getScheme(workspace?: string): Promise<string | undefined> {
    const scheme = core.getInput('scheme')
    if (scheme) {
      return scheme
    }

    if (swiftPM) {
      return getSchemeFromPackage(workspace)
    }
  }
}

function post() {
  deleteAppStoreConnectApiKeyFile()
  deleteKeychain()
  deleteProvisioningProfiles()
}

async function run() {
  await validateSubscription()
  // We use the same entry point for `main` and `post` in action.yml in order to
  // avoid duplicating common logic. To differentiate at runtime, we set some
  // state in `main` for `post` to read.
  const isPost = Boolean(core.getState('isPost'))
  if (isPost) {
    post()
    return
  } else {
    core.saveState('isPost', true)
  }

  try {
    await main()
  } catch (error) {
    await uploadLogs()

    const id = `${process.env.GITHUB_RUN_ID}`
    const slug = process.env.GITHUB_REPOSITORY
    const href = `https://github.com/${slug}/actions/runs/${id}#artifact`

    core.warning(
      `
      We feel you.
      CI failures suck.
      Download the \`.xcresult\` files we just artifact’d.
      They *really* help diagnose what went wrong!
      ${href}
      `.replace(/\s+/g, ' ')
    )

    throw error
  }
}

run().catch((e) => {
  core.setFailed(e)

  if (e instanceof SyntaxError && e.stack) {
    core.error(e.stack)
  }
})

async function uploadLogs() {
  const getFiles: (directory: string) => string[] = (directory) =>
    fs
      .readdirSync(directory)
      .map((entry) => path.join(directory, entry))
      .flatMap((entry) =>
        fs.lstatSync(entry).isDirectory() ? getFiles(entry) : [entry]
      )

  await core.group('Uploading Logs', async () => {
    const xcresults = fs
      .readdirSync('.')
      .filter((entry) => path.extname(entry) == '.xcresult')
    if (xcresults.length === 0) {
      core.warning('strange… no `.xcresult` bundles found')
    }

    const artifact = new DefaultArtifactClient()

    for (const xcresult of xcresults) {
      // random part because GitHub doesn’t yet expose any kind of per-job, per-matrix ID
      // https://github.community/t/add-build-number/16149/17
      const nonce = Math.random()
        .toString(36)
        .replace(/[^a-zA-Z0-9]+/g, '')
        .substr(0, 6)

      const base = path.basename(xcresult, '.xcresult')
      const name = `${base}-${process.env.GITHUB_RUN_NUMBER}.${nonce}.xcresult`
      await artifact.uploadArtifact(name, getFiles(xcresult), '.')
    }
  })
}
