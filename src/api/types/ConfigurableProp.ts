/**
 * This file was auto-generated by Fern from our API Definition.
 */

/**
 * A configuration or input field for a component.
 */
export interface ConfigurableProp {
    /** When building `configuredProps`, make sure to use this field as the key when setting the prop value */
    name?: string;
    type?: string;
    /** Value to use as an input label. In cases where `type` is "app", should load the app via `getApp`, etc. and show `app.name` instead. */
    label?: string;
    /** A description of the prop, shown to the user when configuring the component. */
    description?: string;
    /** If true, this prop does not need to be specified. */
    optional?: boolean;
    /** If true, this prop will be ignored. */
    disabled?: boolean;
    /** If true, should not expose this prop to the user */
    hidden?: boolean;
    /** If true, call `configureComponent` for this prop to load remote options. It is safe, and preferred, given a returned list of { label: string; value: any } objects to set the prop value to { __lv: { label: string; value: any } }. This way, on load, you can access label for the value without necessarily reloading these options */
    remoteOptions?: boolean;
    /** If true, calls to `configureComponent` for this prop support receiving a `query` parameter to filter remote options */
    useQuery?: boolean;
    /** If true, after setting a value for this prop, a call to `reloadComponentProps` is required as the component has dynamic configurable props dependent on this one */
    reloadProps?: boolean;
    /** If true, you must save the configured prop value as a "label-value" object which should look like: { __lv: { label: string; value: any } } because the execution needs to access the label */
    withLabel?: boolean;
}
