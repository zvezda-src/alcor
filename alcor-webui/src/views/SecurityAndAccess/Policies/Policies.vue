<template>
  <b-container fluid="xl">
    <page-title />
    <b-row>
      <b-col md="8">
        <b-row v-if="!modifySSHPolicyDisabled" class="setting-section">
          <b-col class="d-flex align-items-center justify-content-between">
            <dl class="mr-3 w-75">
              <dt>{{ $t('pagePolicies.ssh') }}</dt>
              <dd>
                {{ $t('pagePolicies.sshDescription') }}
              </dd>
            </dl>
            <b-form-checkbox
              id="sshSwitch"
              v-model="sshProtocolState"
              data-test-id="policies-toggle-bmcShell"
              switch
              @change="changeSshProtocolState"
            >
              <span class="sr-only">
                {{ $t('pagePolicies.ssh') }}
              </span>
              <span v-if="sshProtocolState">
                {{ $t('global.status.enabled') }}
              </span>
              <span v-else>{{ $t('global.status.disabled') }}</span>
            </b-form-checkbox>
          </b-col>
        </b-row>
        <b-row class="setting-section">
          <b-col class="d-flex align-items-center justify-content-between">
            <dl class="mt-3 mr-3 w-75">
              <dt>{{ $t('pagePolicies.ipmi') }}</dt>
              <dd>
                {{ $t('pagePolicies.ipmiDescription') }}
              </dd>
            </dl>
            <b-form-checkbox
              id="ipmiSwitch"
              v-model="ipmiProtocolState"
              data-test-id="polices-toggle-networkIpmi"
              switch
              @change="changeIpmiProtocolState"
            >
              <span class="sr-only">
                {{ $t('pagePolicies.ipmi') }}
              </span>
              <span v-if="ipmiProtocolState">
                {{ $t('global.status.enabled') }}
              </span>
              <span v-else>{{ $t('global.status.disabled') }}</span>
            </b-form-checkbox>
          </b-col>
        </b-row>
        <b-row class="setting-section">
          <b-col class="d-flex align-items-center justify-content-between">
            <dl class="mt-3 mr-3 w-75">
              <dt>{{ $t('pagePolicies.vtpm') }}</dt>
              <dd>
                {{ $t('pagePolicies.vtpmDescription') }}
              </dd>
            </dl>
            <b-form-checkbox
              id="vtpmSwitch"
              v-model="vtpmState"
              data-test-id="policies-toggle-vtpm"
              switch
              @change="changeVtpmState"
            >
              <span class="sr-only">
                {{ $t('pagePolicies.vtpm') }}
              </span>
              <span v-if="vtpmState">
                {{ $t('global.status.enabled') }}
              </span>
              <span v-else>{{ $t('global.status.disabled') }}</span>
            </b-form-checkbox>
          </b-col>
        </b-row>
        <b-row class="setting-section">
          <b-col class="d-flex align-items-center justify-content-between">
            <dl class="mt-3 mr-3 w-75">
              <dt>{{ $t('pagePolicies.rtad') }}</dt>
              <dd>
                {{ $t('pagePolicies.rtadDescription') }}
              </dd>
            </dl>
            <b-form-checkbox
              id="rtadSwitch"
              v-model="rtadState"
              data-test-id="policies-toggle-rtad"
              switch
              @change="changeRtadState"
            >
              <span class="sr-only">
                {{ $t('pagePolicies.rtad') }}
              </span>
              <span v-if="rtadState">
                {{ $t('global.status.enabled') }}
              </span>
              <span v-else>{{ $t('global.status.disabled') }}</span>
            </b-form-checkbox>
          </b-col>
        </b-row>
      </b-col>
    </b-row>
  </b-container>
</template>

<script>
import PageTitle from '@/components/Global/PageTitle';

import LoadingBarMixin from '@/components/Mixins/LoadingBarMixin';
import BVToastMixin from '@/components/Mixins/BVToastMixin';

export default {
  name: 'Policies',
  components: { PageTitle },
  mixins: [LoadingBarMixin, BVToastMixin],
  beforeRouteLeave(to, from, next) {
    this.hideLoader();
    next();
  },
  data() {
    return {
      modifySSHPolicyDisabled:
        process.env.VUE_APP_MODIFY_SSH_POLICY_DISABLED === 'true',
    };
  },
  computed: {
    sshProtocolState: {
      get() {
        return this.$store.getters['policies/sshProtocolEnabled'];
      },
      set(newValue) {
        return newValue;
      },
    },
    ipmiProtocolState: {
      get() {
        return this.$store.getters['policies/ipmiProtocolEnabled'];
      },
      set(newValue) {
        return newValue;
      },
    },
    rtadState: {
      get() {
        if (this.$store.getters['policies/rtadEnabled'] === 'Enabled') {
          return true;
        } else {
          return false;
        }
      },
      set(newValue) {
        return newValue;
      },
    },
    vtpmState: {
      get() {
        if (this.$store.getters['policies/vtpmEnabled'] === 'Enabled') {
          return true;
        } else {
          return false;
        }
      },
      set(newValue) {
        return newValue;
      },
    },
  },
  created() {
    this.startLoader();
    Promise.all([
      this.$store.dispatch('policies/getBiosStatus'),
      this.$store.dispatch('policies/getNetworkProtocolStatus'),
    ]).finally(() => this.endLoader());
  },
  methods: {
    changeIpmiProtocolState(state) {
      this.$store
        .dispatch('policies/saveIpmiProtocolState', state)
        .then((message) => this.successToast(message))
        .catch(({ message }) => this.errorToast(message));
    },
    changeSshProtocolState(state) {
      this.$store
        .dispatch('policies/saveSshProtocolState', state)
        .then((message) => this.successToast(message))
        .catch(({ message }) => this.errorToast(message));
    },
    changeRtadState(state) {
      this.$store
        .dispatch('policies/saveRtadState', state ? 'Enabled' : 'Disabled')
        .then((message) => this.successToast(message))
        .catch(({ message }) => this.errorToast(message));
    },
    changeVtpmState(state) {
      this.$store
        .dispatch('policies/saveVtpmState', state ? 'Enabled' : 'Disabled')
        .then((message) => this.successToast(message))
        .catch(({ message }) => this.errorToast(message));
    },
  },
};
</script>

<style lang="scss" scoped>
.setting-section {
  border-bottom: 1px solid gray('300');
}
</style>
