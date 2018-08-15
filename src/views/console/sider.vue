<template>
    <div class="sider-view">
        <Menu theme="dark" active-name="1" width="auto" @on-select="MenuSelected">
            <MenuItem name="status">
                <Icon size="24" type="md-speedometer" />
                Status
            </MenuItem>
            <MenuItem name="config">
                <Icon size="24" type="md-settings" />
                Configuration
            </MenuItem>
            <MenuItem name="accounts">
                <Icon size="24" type="md-contacts" />
                Accounts
            </MenuItem>
            <MenuItem name="router">
                <Icon size="24" type="md-list" />
                Router
            </MenuItem>
        </Menu>
        this is from Sider, data is {{ message }}
    </div>
</template>
<script>
    export default {
        props: ['data'],
        data: function () {
            return {
                message: this.data
            }
        },
        methods: {
            MenuSelected: function (value) {
                this.message = value;
                this.$emit('set_content_data', value);
            }
        }
    }
</script>
